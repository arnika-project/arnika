package main

import (
	"encoding/json"
	"log"
	"net/http"
)

const Port = "8080"

var data = `{
	"/api/v1/keys/CONSA/enc_keys": {
		"GET": {
			"query_parameters": {},
			"response": {
				"status": 200,
				"headers": {
					"Content-Type": "application/json"
				},
				"body": {
					"keys": [
						{
							"key": "wsybeAl6RwvP48e538L/SN9b8vtTUsvk1tL7YT4sgF0=",
							"key_ID": "cba66e30-85d8-447e-ad00-f89042e282d8"
						}
					]
				}
			}
		}
	},
	"/api/v1/keys/CONSA/dec_keys": {
		"GET": {
			"query_parameters": {
				"key_ID": "cba66e30-85d8-447e-ad00-f89042e282d8"
			},
			"response": {
				"status": 200,
				"headers": {
					"Content-Type": "application/json"
				},
				"body": {
					"keys": [
						{
							"key": "wsybeAl6RwvP48e538L/SN9b8vtTUsvk1tL7YT4sgF0=",
							"key_ID": "cba66e30-85d8-447e-ad00-f89042e282d8"
						}
					]
				}
			}
		}
	},
	"/api/v1/keys/CONSB/enc_keys": {
		"GET": {
			"query_parameters": {},
			"response": {
				"status": 200,
				"headers": {
					"Content-Type": "application/json"
				},
				"body": {
					"keys": [
						{
							"key": "wsybeAl6RwvP48e538L/SN9b8vtTUsvk1tL7YT4sgF0=",
							"key_ID": "cba66e30-85d8-447e-ad00-f89042e282d8"
						}
					]
				}
			}
		}
	},
	"/api/v1/keys/CONSB/dec_keys": {
		"GET": {
			"query_parameters": {
				"key_ID": "cba66e30-85d8-447e-ad00-f89042e282d8"
			},
			"response": {
				"status": 200,
				"headers": {
					"Content-Type": "application/json"
				},
				"body": {
					"keys": [
						{
							"key": "wsybeAl6RwvP48e538L/SN9b8vtTUsvk1tL7YT4sgF0=",
							"key_ID": "cba66e30-85d8-447e-ad00-f89042e282d8"
						}
					]
				}
			}
		}
	}
}`

const LOG = "[%d] %s %s"

type mockData map[string]map[string]mockEndpoint

type mockEndpoint struct {
	QueryParameters map[string]string `json:"query_parameters"`
	Response        response
}

type response struct {
	Status  int
	Headers map[string]string
	Body    any
}

var mock mockData

func main() {
	if err := json.Unmarshal([]byte(data), &mock); err != nil {
		panic("error parsing mock data json: " + err.Error())
	}

	for endpoint := range mock {
		http.HandleFunc(endpoint, handler)
	}

	if err := http.ListenAndServe(":"+Port, nil); err != nil {
		panic("error starting server: " + err.Error())
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := mock[r.URL.Path][r.Method]
	for k, v := range data.Response.Headers {
		w.Header().Set(k, v)
	}
	if len(data.QueryParameters) > 0 {
		queryParams := r.URL.Query()
		if len(queryParams) == 0 {
			notFoundResponse(w, r)
			return
		}
		for k, v := range data.QueryParameters {
			if val, ok := queryParams[k]; !ok || (len(val) == 0 || len(val) > 0 && val[0] != v) {
				notFoundResponse(w, r)
				return
			}
		}
	}
	w.WriteHeader(data.Response.Status)
	body, err := json.Marshal(data.Response.Body)
	if err != nil {
		internlServerResponse(w, r, err)
		return
	}
	if _, err := w.Write(body); err != nil {
		internlServerResponse(w, r, err)
		return
	}
	log.Printf(LOG, http.StatusOK, r.Method, r.URL.Path+getQueryParamaters(r))
}

func notFoundResponse(w http.ResponseWriter, r *http.Request) {
	log.Printf(LOG, http.StatusNotFound, r.Method, r.URL.Path+getQueryParamaters(r))
	w.WriteHeader(http.StatusNotFound)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("404 page not found\n"))
}

func internlServerResponse(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf(LOG, http.StatusInternalServerError, r.Method, r.URL.Path+getQueryParamaters(r))
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("error writing response body: " + err.Error()))
}

func getQueryParamaters(r *http.Request) string {
	if r.URL.RawQuery != "" {
		return "?" + r.URL.RawQuery
	}
	return ""
}
