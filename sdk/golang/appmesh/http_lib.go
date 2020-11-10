package appmesh

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

//skip https ssl certfication
var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

//Get http get method
func Get(url string, reqToken string, params map[string]string, headers map[string]string, timeoutSeconds int) (*http.Response, error) {
	//new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	//add params
	q := req.URL.Query()
	if params != nil {
		for key, val := range params {
			q.Add(key, val)
		}
		req.URL.RawQuery = q.Encode()
	}
	//add headers
	if headers != nil {
		for key, val := range headers {
			req.Header.Add(key, val)
		}
	}
	// add token
	if reqToken != "" {
		req.Header.Set("Authorization", "Bearer "+reqToken)
	}
	//http client
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * time.Duration(timeoutSeconds),
	}
	log.Printf("Go GET URL : %s \n", req.URL.String())
	return client.Do(req)
}

//Post http post method
func Post(url string, reqToken string, body map[string]interface{}, params map[string]string, headers map[string]string, timeoutSeconds int) (*http.Response, error) {
	//add post body
	var bodyJson []byte
	var req *http.Request
	if body != nil {
		var err error
		bodyJson, err = json.Marshal(body)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJson))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	req.Header.Set("Content-type", "application/json")
	// add token
	if reqToken != "" {
		req.Header.Set("Authorization", "Bearer "+reqToken)
	}
	//add params
	q := req.URL.Query()
	if params != nil {
		for key, val := range params {
			q.Add(key, val)
		}
		req.URL.RawQuery = q.Encode()
	}
	//add headers
	if headers != nil {
		for key, val := range headers {
			req.Header.Add(key, val)
		}
	}
	//http client
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * time.Duration(timeoutSeconds),
	}
	log.Printf("Go POST URL : %s \n", req.URL.String())

	return client.Do(req)
}
