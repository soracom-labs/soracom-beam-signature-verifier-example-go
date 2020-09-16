package soracom

import (
	"net/http"
	"os"
	"testing"
)

type Testcase struct {
	name         string
	sharedSecret string
	err          error
	headers      map[string][]string
}

func TestVerifyBeamSignature(t *testing.T) {
	var validTestcases = []Testcase{
		{
			"cellular_with_imei_uppercase",
			"secret",
			nil,
			map[string][]string{
				"X-SORACOM-IMSI": {
					"295100000000001",
				},
				"X-SORACOM-IMEI": {
					"012345678901234",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"125d84ef000ed210da7a4de94fe601589295370c9e465982c8ddb84dcb7e779e", // TODO: calculate in dynamic
				},
			},
		},
		{
			"cellular_with_imei_lowercase",
			"secret",
			nil,
			map[string][]string{
				"x-soracom-imsi": {
					"295100000000001",
				},
				"x-soracom-imei": {
					"012345678901234",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"125d84ef000ed210da7a4de94fe601589295370c9e465982c8ddb84dcb7e779e", // TODO: calculate in dynamic
				},
			},
		},
		{
			"cellular_without_imei",
			"secret",
			nil,
			map[string][]string{
				"X-SORACOM-IMSI": {
					"295100000000001",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"a15174afa6e4a4ffa0f9c44e6085e9b6f2b5f0cf2c3437bf46bdd9bf8514f51b", // TODO: calculate in dynamic
				},
			},
		},
		{
			"sigfox",
			"secret",
			nil,
			map[string][]string{
				"X-SORACOM-SIGFOX-DEVICE-ID": {
					"FFFFFF", // TODO: uppercase? lowercase?
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"f9e3364679192f572318101e7fea3186d01c2f751b661735875116463a2db466", // TODO: calculate in dynamic
				},
			},
		},
		{
			"lorawan",
			"secret",
			nil,
			map[string][]string{
				"X-SORACOM-LORA-DEVICE-ID": {
					"0123456789abcdef",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"4eed6b68e7ac8093c375ef6d2346e510ccaa08afc8292f5e613271aaa5b13a28", // TODO: calculate in dynamic, uppercase? lowercase?
				},
			},
		},
		{
			"inventory",
			"secret",
			nil,
			map[string][]string{
				"X-DEVICE-ID": {
					"d-0123456789acbdefghij",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"ab59fbf1a5b68cf7d3547342c40f6f170ed5a2d07017d810e3a39ee4a654aa6d", // TODO: calculate in dynamic, uppercase? lowercase?
				},
			},
		},
		{
			"cellular_with_imei_uppercase_no_signature_version",
			"secret",
			ErrCommonParameterMissing,
			map[string][]string{
				"X-SORACOM-IMSI": {
					"295100000000001",
				},
				"X-SORACOM-IMEI": {
					"012345678901234",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE": {
					"125d84ef000ed210da7a4de94fe601589295370c9e465982c8ddb84dcb7e779e", // TODO: calculate in dynamic
				},
			},
		},
		{
			"cellular_with_imei_uppercase_unsupported_signature_version",
			"secret",
			ErrUnsupportedSignatureVersion,
			map[string][]string{
				"X-SORACOM-IMSI": {
					"295100000000001",
				},
				"X-SORACOM-IMEI": {
					"012345678901234",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20141001",
				},
				"X-SORACOM-SIGNATURE": {
					"125d84ef000ed210da7a4de94fe601589295370c9e465982c8ddb84dcb7e779e", // TODO: calculate in dynamic
				},
			},
		},
		{
			"no_device_type",
			"secret",
			ErrDeviceDetectFailed,
			map[string][]string{
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"125d84ef000ed210da7a4de94fe601589295370c9e465982c8ddb84dcb7e779e", // TODO: calculate in dynamic
				},
			},
		},
		{
			"no_shared_secret",
			"",
			ErrSharedSecretMissing,
			map[string][]string{},
		},
		{
			"cellular_invalid_signature",
			"secret",
			ErrSignatureVerifyFailed,
			map[string][]string{
				"X-SORACOM-IMSI": {
					"295100000000001",
				},
				"X-SORACOM-IMEI": {
					"012345678901234",
				},
				"X-SORACOM-TIMESTAMP": {
					"1443571200000",
				},
				"X-SORACOM-SIGNATURE-VERSION": {
					"20151001",
				},
				"X-SORACOM-SIGNATURE": {
					"01234",
				},
			},
		},
	}
	for _, testcase := range validTestcases {
		t.Run(testcase.name, func(t *testing.T) {
			_ = os.Setenv("SORACOM_BEAM_SHARED_SECRET", testcase.sharedSecret)
			request, _ := http.NewRequest(http.MethodPost, "/", nil)
			for key, values := range testcase.headers {
				for _, value := range values {
					request.Header.Add(key, value)
				}
			}

			err := verifyBeamSignature(request)
			if err != testcase.err {
				t.Errorf("%#v", err)
			}

		})
	}
}
