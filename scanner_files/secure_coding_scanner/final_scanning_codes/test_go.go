package main

import (
	"fmt"
	"net/http"
)

func main() {
	// This is a simple Go code that has some security issues
	http.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		// Security issue: Potential SQL injection
		query := r.URL.Query().Get("query")
		if query != "" {
			sql := "SELECT * FROM users WHERE username='" + query + "'"
			// Execute SQL query (insecure)
			_, err := db.Exec(sql)
			if err != nil {
				fmt.Println(err)
			}
		}
		// Security issue: Unvalidated input
		input := r.URL.Query().Get("input")
		if input != "" {
			fmt.Println("Received input:", input)
		}
	})

	http.ListenAndServe(":8080", nil)
}
