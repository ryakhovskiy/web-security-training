package pawpal

import (
	"crypto/subtle"
	"fmt"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(payload any, providedKey []byte, expectedKey []byte) WebhookVerification {
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}
	status, ok := payloadRecord["status"]
	if !ok || status != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}

	if subtle.ConstantTimeCompare(providedKey, expectedKey) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized, OrderID: int64(orderID)}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
