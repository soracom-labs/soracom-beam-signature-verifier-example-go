package soracom

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
)

var (
	// ErrSharedSecretMissing ...
	ErrSharedSecretMissing = errors.New("Shared secret is missing, please check SORACOM_BEAM_SHARED_SECRET environment variable")
	// ErrDeviceDetectFailed ...
	ErrDeviceDetectFailed = errors.New("imsi, sigfoxDeviceID or loraDeviceID are missing")
	// ErrSignatureVerifyFailed ...
	ErrSignatureVerifyFailed = errors.New("Failed to verify the provided signature")
	// ErrCommonParameterMissing ...
	ErrCommonParameterMissing = errors.New("timestamp, providedSignature or signatureVersion are missing")
	// ErrUnsupportedSignatureVersion ...
	ErrUnsupportedSignatureVersion = errors.New("Unsupported SORACOM Beam signature version detected")
)

// BeamSignatureVerifier verify signature in SORACOM Beam request header.
func BeamSignatureVerifier(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := verifyBeamSignature(r)
		if err != nil {
			switch err {
			case ErrSharedSecretMissing:
				log.Println(err)
				http.Error(w, "Something went wrong", http.StatusInternalServerError)
				return
			default:
				log.Println(err)
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func verifyBeamSignature20151001(sharedSecret, imei, imsi, sigfoxDeviceID, loraDeviceID, deviceID, timestamp, providedSignature string) error {
	var signatureString string

	// Concat headers to create signature string
	signatureString = sharedSecret
	// Cellular
	if imsi != "" {
		if 0 < len(imei) {
			signatureString = sharedSecret + "x-soracom-imei=" + imei
		}
		signatureString = signatureString + "x-soracom-imsi=" + imsi
	} else if sigfoxDeviceID != "" {
		// Sigfox
		signatureString = signatureString + "x-soracom-sigfox-device-id=" + sigfoxDeviceID
	} else if loraDeviceID != "" {
		// LoRaWAN
		signatureString = signatureString + "x-soracom-lora-device-id=" + loraDeviceID
	} else if deviceID != "" {
		// Inventory Notify
		signatureString = signatureString + "x-device-id=" + deviceID
	} else {
		return ErrDeviceDetectFailed
	}
	signatureString = signatureString + "x-soracom-timestamp=" + timestamp

	// Calculate signature
	hash := sha256.Sum256([]byte(signatureString))
	calculatedSignature := hex.EncodeToString(hash[:])
	if providedSignature != calculatedSignature {
		return ErrSignatureVerifyFailed
	}
	return nil
}

func verifyBeamSignature(r *http.Request) error {
	sharedSecret := os.Getenv("SORACOM_BEAM_SHARED_SECRET")
	imsi := r.Header.Get("X-SORACOM-IMSI")
	imei := r.Header.Get("X-SORACOM-IMEI")
	sigfoxDeviceID := r.Header.Get("X-SORACOM-SIGFOX-DEVICE-ID")
	loraDeviceID := r.Header.Get("X-SORACOM-LORA-DEVICE-ID")
	deviceID := r.Header.Get("X-DEVICE-ID")
	timestamp := r.Header.Get("X-SORACOM-TIMESTAMP")
	providedSignature := r.Header.Get("X-SORACOM-SIGNATURE")
	signatureVersion := r.Header.Get("X-SORACOM-SIGNATURE-VERSION")

	if sharedSecret == "" {
		return ErrSharedSecretMissing
	}
	if timestamp == "" || providedSignature == "" || signatureVersion == "" {
		return ErrCommonParameterMissing
	}

	switch signatureVersion {
	case "20151001":
		err := verifyBeamSignature20151001(sharedSecret, imei, imsi, sigfoxDeviceID, loraDeviceID, deviceID, timestamp, providedSignature)
		if err != nil {
			return err
		}
		break
	default:
		return ErrUnsupportedSignatureVersion
	}
	return nil
}
