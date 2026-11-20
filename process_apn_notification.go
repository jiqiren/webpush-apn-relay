package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sideshow/apns2"
	log "github.com/sirupsen/logrus"
)

type Message struct {
	isProduction   bool
	notification   *apns2.Notification
	unsubscribeUrl string
	requestLog     *log.Entry // Carries the request-id field into the worker goroutine
	ctx            context.Context
}

func apnNotificationsWorker(workerId int, httpClient *http.Client) {
	log.Info(fmt.Sprintf("starting worker %d", workerId))
	defer log.Info(fmt.Sprintf("stopping worker %d", workerId))

	for msg := range messageChan {
		processApnNotificationMessage(msg, httpClient, workerId)
	}
}

func processApnNotificationMessage(msg *Message, httpClient *http.Client, workerId int) {
	workersActive.Inc()
	defer workersActive.Dec()

	environment := environmentName(msg.isProduction)

	// The timer starts at worker pickup, not at request arrival, so it measures
	// the APNs round-trip and excludes queue wait. Queue wait is observable
	// separately via relay_queue_depth.
	start := time.Now()

	var client *apns2.Client
	if msg.isProduction {
		client = productionClient
	} else {
		client = developmentClient
	}

	res, err := client.PushWithContext(msg.ctx, msg.notification)
	pushDurationSeconds.WithLabelValues(environment).Observe(time.Since(start).Seconds())

	if err != nil {
		recordPush(msg.isProduction, "error")
		msg.requestLog.Error(fmt.Sprintf("Push error: %s", err))
		return
	}

	recordApnsStatus(msg.isProduction, res.StatusCode)

	if !res.Sent() {
		recordPush(msg.isProduction, "rejected")
		unsubscribed := false

		// 410 status means that the token is invalid. This is a definitive error, and we should remove the subscription
		// from the originating server to avoid continuing sending requests that will never work again.
		// See https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
		if msg.unsubscribeUrl != "" && res.StatusCode == 410 {
			unsubscribed = unsubscribe(msg.unsubscribeUrl, httpClient, msg.ctx, msg.requestLog)
		}

		msg.requestLog.WithFields(log.Fields{
			"status-code":  res.StatusCode,
			"apns-id":      res.ApnsID,
			"reason":       res.Reason,
			"unsubscribed": unsubscribed,
		}).Error(fmt.Sprintf("Failed to send notification (%v)", res.StatusCode))

		return
	}

	recordPush(msg.isProduction, "sent")

	msg.requestLog.WithFields(log.Fields{
		"status-code":  res.StatusCode,
		"apns-id":      res.ApnsID,
		"reason":       res.Reason,
		"device-token": msg.notification.DeviceToken,
		"expiration":   msg.notification.Expiration,
		"priority":     msg.notification.Priority,
		"collapse-id":  msg.notification.CollapseID,
	}).Info(fmt.Sprintf("Sent notification (%v)", res.StatusCode))
}

func unsubscribe(unsubscribeUrl string, httpClient *http.Client, ctx context.Context, requestLog *log.Entry) bool {
	unsubscribeReq, reqErr := http.NewRequestWithContext(ctx, "DELETE", unsubscribeUrl, nil)

	if reqErr != nil {
		recordUnsubscribe("build_request_error")
		requestLog.WithFields(log.Fields{
			"error":           reqErr.Error(),
			"unsubscribe-url": unsubscribeUrl,
		}).Error("Failed to create HTTP request for unsubscribe")
		return false
	}

	unsubscribeReq.Header.Set("User-Agent", userAgent())

	unsubscribeResp, respErr := httpClient.Do(unsubscribeReq)
	if respErr != nil {
		recordUnsubscribe("error")
		requestLog.WithFields(log.Fields{
			"error":           respErr.Error(),
			"unsubscribe-url": unsubscribeUrl,
		}).Error("Failed to send unsubscribe request")
		return false
	}

	if unsubscribeResp.StatusCode == 200 {
		recordUnsubscribe("ok")
		return true
	} else {
		recordUnsubscribe("error")
		requestLog.WithFields(log.Fields{
			"status-code":     unsubscribeResp.StatusCode,
			"unsubscribe-url": unsubscribeUrl,
		}).Error(fmt.Sprintf("Failed to unsubscribe for notification (%v)", unsubscribeResp.StatusCode))
		return false
	}
}
