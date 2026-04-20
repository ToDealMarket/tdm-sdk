package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

func main() {
	body := []byte(`{"requestId":"req_go_demo","resourceId":"premium:api","operation":"premium:api","tokenOrUuid":"go-agent","priceMinor":5}`)

	req, err := http.NewRequest(http.MethodPost, "https://tdm.todealmarket.com/authorize", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TDM-Session-Token", "tdm_session_replace_me")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	fmt.Println(string(raw))
}

