package bipbf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// DiscordBot represents a simple client that sends messages to a Discord channel
// using a webhook URL.
type DiscordBot struct {
	webhookURL string
}

// NewDiscordBot initializes a new DiscordBot with the provided Discord webhook URL.
func NewDiscordBot(webhookURL string) *DiscordBot {
	return &DiscordBot{
		webhookURL: webhookURL,
	}
}

// SendMessage sends a simple text message to the Discord channel via the configured webhook URL.
func (bot *DiscordBot) SendMessage(message string) error {
	// Build payload for Discord webhook
	payload := struct {
		Content string `json:"content"`
	}{
		Content: message,
	}

	// Convert payload to JSON
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON payload: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", bot.webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	// Check for non-2xx response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received non-2xx status code: %d", resp.StatusCode)
	}

	return nil
}
