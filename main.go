package main

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	//"runtime" 	//fmt.Println(runtime.NumGoroutine())
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"strings"
	"sync"
	"time"
)

type response struct {
	RequestRecievedAt int64
	ResponseSentAt    int64
	TimeToProcess     int64
}

type results struct {
	Mean  int64
	Total int64
	Max   int64
	Min   int64
}

var publicKey *rsa.PublicKey
var hashInterface hash.Hash
var blankLabel []byte

var runResults results

var connectionString []string

func main() {
	//Variables about how many goroutines to start/number of requests to make
	numRequests := flag.Int("r", 1000, "number of requests to make")
	numGoRoutines := flag.Int("g", 4, "number of request making go routines")
	//Example flag usage: -h="http://52.11.171.109:8080&52.11.171.109:8000"
	url := flag.String("h", "http://127.0.0.1:8080&:8000", "connecting string http-url&tcp-url")

	flag.Parse()

	connectionString = strings.Split(*url, "&")

	file := initLogger()
	responseChannel := make(chan response, *numRequests)
	defer file.Close()

	//Set up waitgroups
	var wg sync.WaitGroup
	var messageWg sync.WaitGroup
	var finishedTestWg sync.WaitGroup

	runResults = results{Mean: 0, Max: -1, Min: 1<<63 - 1}

	//Polling master server
	//Runs a function listening to messages from server
	//When a message is recieved we return the function to stop blocking and continue with the rest of the code
	startMessage := make(chan int)
	doneMessage := make(chan int)
	go pollMasterServer(startMessage, doneMessage, &finishedTestWg)

	func() {
		for {
			select {
			case _ = <-startMessage:
				fmt.Println("Starting bots")
				return
			}
		}
	}()

	//Start logging
	go logFunc(responseChannel, &messageWg, file)

	//Init a channel that workers will read off of
	requestsToMake := make(chan int, *numRequests)
	for i := 0; i < *numRequests; i++ {
		requestsToMake <- i
	}

	//Start the response
	now := time.Now().UnixNano()
	for i := 0; i < *numGoRoutines; i++ {
		wg.Add(1)
		go work(responseChannel, &messageWg, requestsToMake, &wg)
	}
	wg.Wait()
	fmt.Printf("Took %vms seconds time to complete the runs\n", (time.Now().UnixNano()-now)/1000000)
	messageWg.Wait()
	doneMessage <- 1
	runResults.Mean = runResults.Total / int64(*numRequests)
	fmt.Printf("%+v\n", runResults)
	finishedTestWg.Wait()
}

//Work is a worker.
//Message chan is the channel that response will be written to - gets passed to makeRequest
//Message WG is the wait group for logging message. Incremented here and decremented in the logger function
//Work is a channel built to concurrently read out work to do. Nothing of importance in there
//wg is the WG for the work function. If there is no more work to do wg is called done
//We have to label the for because breaks break out of select or for, in this case we want to break out of for
func work(messageChan chan response, messageWg *sync.WaitGroup, work chan int, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case _ = <-work:
			messageWg.Add(1)
			makeRequest(messageChan)
		default:
			return
		}
	}
}

func initLogger() *os.File {
	file, err := os.OpenFile("log.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	return file
}

//Change these panics
func makeRequest(messageChan chan response) {
	resp, err := http.Get(connectionString[0])
	if err != nil {
		panic(err)
		//fmt.Println(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
		//fmt.Println(err)
	}
	var serverResponse response
	json.Unmarshal(body, &serverResponse)
	messageChan <- serverResponse
}

//TCP long poller?
func pollMasterServer(startMessage chan int, doneMessage chan int, finishedTestWg *sync.WaitGroup) {
	finishedTestWg.Add(1)
	for {
		conn, err := net.Dial("tcp", connectionString[1])
		if err != nil {
			fmt.Println("Failed to connect, retrying in 10..")
			time.Sleep(10 * time.Second)
			continue
		}
		fmt.Fprintf(conn, "Ping\n")
		readServerMessages(conn, startMessage, doneMessage, finishedTestWg)
		//Send first message to get RSA key
	}
}

func readServerMessages(conn net.Conn, startMessage chan int, doneMessage chan int, finishedTestWg *sync.WaitGroup) {
	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(err)
			break
		}
		if strings.HasPrefix(message, "RSAKEY::") {
			encodedPublicKey := strings.TrimPrefix(message, "RSAKEY::")
			encodedPublicKey = strings.TrimSuffix(encodedPublicKey, "\n")
			decodedPublicKey, err := base64.StdEncoding.DecodeString(encodedPublicKey)
			if err != nil {
				panic(err)
			}
			publicKey, err = buildPublicKey(decodedPublicKey)
			if err != nil {
				panic(err)
			}
			encryptedMessage, err := rsa.EncryptOAEP(hashInterface, rand.Reader, publicKey, []byte("TESTPASS"), blankLabel)
			if err != nil {
				fmt.Printf("Error encrypting the message %v\n", err)
			}
			encryptedEncodedMessage := base64.StdEncoding.EncodeToString(encryptedMessage)
			fmt.Fprintf(conn, "%s\n", encryptedEncodedMessage)
			continue
		}
		fmt.Println(string(message))
		if string(message) == "start\n" {
			encryptedMessage, err := rsa.EncryptOAEP(hashInterface, rand.Reader, publicKey, []byte("starting"), blankLabel)
			if err != nil {
				fmt.Printf("Error encrypting the message %v\n", err)
			}
			encryptedEncodedMessage := base64.StdEncoding.EncodeToString(encryptedMessage)
			fmt.Fprintf(conn, "%s\n", encryptedEncodedMessage)
			startMessage <- 1
			<-doneMessage
			//Marshaling JSON here
			resultsMessage, _ := json.Marshal(runResults)
			//End Marshalling JSON
			encryptedMessage, err = rsa.EncryptOAEP(hashInterface, rand.Reader, publicKey, append([]byte("done:"), resultsMessage...), blankLabel)
			if err != nil {
				fmt.Printf("Error encrypting the message %v\n", err)
			}
			encryptedEncodedMessage = base64.StdEncoding.EncodeToString(encryptedMessage)
			fmt.Fprintf(conn, "%s\n", encryptedEncodedMessage)
			finishedTestWg.Done()
		}
	}
}

func buildPublicKey(pkixBytes []byte) (*rsa.PublicKey, error) {
	hashInterface = md5.New()
	publicKeyInterface, err := x509.ParsePKIXPublicKey(pkixBytes)
	if err != nil {
		//Panic making interface from public key
		return &rsa.PublicKey{}, err
	}

	//THis is a type assertion -- https://golang.org/ref/spec#Type_assertions
	public, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		//Panic issues creating interface
		fmt.Println("BADDDD")
	}
	return public, nil
}

//responseChannel, messageWg
func logFunc(messageChan chan response, wg *sync.WaitGroup, file *os.File) {
	//Reads from channel and logs
	for {
		select {
		case message := <-messageChan:
			runResults.Max = max(runResults.Max, message.TimeToProcess)
			runResults.Min = min(runResults.Min, message.TimeToProcess)
			runResults.Total += message.TimeToProcess
			file.WriteString(fmt.Sprintf("%+v\n", message))
			wg.Done()
		}
	}
}

func min(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
