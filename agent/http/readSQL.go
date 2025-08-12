package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// PingLog represents a single log entry in the pingLog table
type PingLog struct {
	LogTime  string  `json:"logtime"`
	DSCP     int     `json:"dscp"`
	Target   string  `json:"target"`
	MaxDelay float64 `json:"maxdelay"`
	MinDelay float64 `json:"mindelay"`
	AvgDelay float64 `json:"avgdelay"`
	LossPk   int     `json:"losspk"`
}

func main() {
	// Connect to the SQLite database
	db, err := sql.Open("sqlite3", "../database/pingLog.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to the database: %s\n", err)
	}
	defer db.Close()

	// Define the time range for the query
	startTime := "2025-04-01 00:00:00"
	endTime := "2025-04-10 23:59:59"

	// Query the database for logs within the specified time range
	rows, err := db.Query(`
        SELECT logtime, dscp, target, maxdelay, mindelay, avgdelay, losspk
        FROM pingLog
        WHERE logtime BETWEEN ? AND ?`, startTime, endTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to query: %s\n", err)
	}
	defer rows.Close()

	// Iterate over the query results and store them in a slice
	var logs []PingLog
	for rows.Next() {
		var log PingLog
		err := rows.Scan(&log.LogTime, &log.DSCP, &log.Target, &log.MaxDelay, &log.MinDelay, &log.AvgDelay, &log.LossPk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to query: %s\n", err)
		}
		// Delete the following line with NaN values
		if log.MaxDelay != log.MaxDelay || log.MinDelay != log.MinDelay || log.AvgDelay != log.AvgDelay || log.LossPk != log.LossPk {
			continue
		}
		logs = append(logs, log)
	}

	// Check for errors from iterating over rows
	if err = rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to iterate over rows: %s\n", err)
	}

	// Convert the logs to JSON format
	jsonData, err := json.Marshal(logs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to convert the logs to JSON format: %s\n", err)
	}

	// Output the JSON data
	//fmt.Println(string(jsonData))

	// Save the JSON data to a file
	fmt.Println("Saving the JSON data to a file...")
	err = saveJSONToFile(jsonData, "pingLogs.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save the JSON data to a file: %s\n", err)
	}
}

// saveJSONToFile saves the JSON data to a file
func saveJSONToFile(data []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}
