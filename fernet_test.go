package fernet

import (
	"strconv"
	"testing"
	"time"
)

// See https://github.com/fernet/spec/blob/master/generate.json
func TestSpecGenerate(t *testing.T) {
	var (
		token  = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="
		now    = time.Date(1985, 10, 26, 8, 20, 0, 0, time.UTC)
		msg    = "hello"
		secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
		ivfn   = func(a []byte) error {
			for i := 0; i < 16; i++ {
				a[i] = byte(i)
			}
			return nil
		}
	)
	tok, err := encrypt(msg, secret, now, ivfn)
	if err != nil {
		t.Fatalf("encrypt error: %s", err)
	}
	if tok != token {
		t.Fatalf("wrong token: got %q, want %q", tok, token)
	}
	plaintext, err := Decrypt(tok, secret, now, time.Minute)
	if err != nil {
		t.Fatalf("decrypt error: %s", err)
	}
	if plaintext != msg {
		t.Fatalf("wrong message: got %q, want %q", plaintext, msg)
	}
}

// See https://github.com/fernet/spec/blob/master/verify.json
func TestSpecVerify(t *testing.T) {
	var (
		token  = "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="
		now    = time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC)
		ttl    = time.Minute
		msg    = "hello"
		secret = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
	)
	plaintext, err := Decrypt(token, secret, now, ttl)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != msg {
		t.Fatalf("Decrypt returned %q, want %q", plaintext, msg)
	}
}

// See https://github.com/fernet/spec/blob/master/invalid.json
func TestSpecInvalid(t *testing.T) {
	var tests = []struct {
		desc   string
		token  string
		now    time.Time
		ttl    time.Duration
		secret string
	}{
		{
			desc:   "incorrect mac",
			token:  "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==",
			now:    time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
		{
			desc:   "too short",
			token:  "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==",
			now:    time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
		{
			desc:   "invalid base64",
			token:  "%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
			now:    time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
		{
			desc:   "payload size not multiple of block size",
			token:  "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9uGib28Xe5vz6oxq5nmxbx_v7mrfyudzUm",
			now:    time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
		{
			desc:   "payload padding error",
			token:  "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYRLQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==",
			now:    time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
		{
			desc:   "far-future TS (unacceptable clock skew)",
			token:  "gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==",
			now:    time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
		{
			desc:   "expired TTL",
			token:  "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
			now:    time.Date(1985, time.October, 26, 8, 21, 31, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
		{
			desc:   "incorrect IV (causes padding error)",
			token:  "gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtDBRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ==",
			now:    time.Date(1985, time.October, 26, 8, 20, 01, 0, time.UTC),
			ttl:    time.Minute,
			secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := Decrypt(tt.token, tt.secret, tt.now, tt.ttl); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// Verifies that decrypt(encrypt(...)) recovers the original message.
func TestReversible(t *testing.T) {
	var tests = []struct {
		secret string
		msg    string
	}{
		{"wGknIOZNpk-KFe5_t5gxH6Eac9gxTv6SlOHVJnSyEVw=", "jW9[.uYJmeicKI e]yW;\\&"},
		{"2RrwbX4DMzW67gFZuvAlEnP6UIWq31YnlQbr_FBIc7E=", ""},
		{"DQM4LyAEaM0WaysBjQZY-aJViq4rBoDL5f95pXBoO1g=", ",iCg9%qBtUL,of=CD3tRclFvbu+Ga$0t'*mY\"`U 8DT:2-Kz;[VYDy-}}0jYVa.xr5R\"O`"},
		{"NUUaPEJ50Bws0VzjDBlyaVJkbXkfgjn8nrK2xA-3PwQ=", "D;1bvg%2?@'8G|v+NWk[\"RnNRU2=,0yX7B\\X1j(,-\\]Q_\\U.cy3sA!GQ:X&/)qCd"},
		{"yQ58eTeUIficSxvOr2ZENLlCuVr10cJ9V_sNjml91cs=", "[O;@7[DI0D@f{EN*4hF*]|i+N]s)_S/bF"},
		{"musokEaOe7OAuCiW3E_Bc4aouWJ-X9Ns9Trp11TMmcw=", "Fa2Vf,Lk,UE'^E'Iu=Uz=Oxgl[q!O6y!crwRE&wa86:D?6Eiij]W# @nnxygT"},
		{"vZzhoxhRWIkcCNS4264Y0VGHgewof6mFJEU_LPksPIE=", "8!%rLW):$ht"},
		{"VQE05iqyLRVpZUpZyjOtOhagUnyATvf38AjPvneCahA=", "DC)%xn@%+qx-jZ*&"},
		{"O48IEZ2RsyDKJ4-O_-paw78760zL0XkKowAtNcegdg0=", "SKx[wV&!/DJ#vKHq o{J`_?jw%eW"},
		{"j6HXdeY5APQeXAQEQxvK-BqTM80ppIBdfMw5JyPacFA=", "yA #?7ju?lF#>dO_^k* 2w=z0?$n=qS<%4t4AN\"0b,$iM@s?5681d`kYOGgo&Ggmk;kkBm;l/&FJRKp2E:Hbw"},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			now := time.Now()
			tok, err := Encrypt(tt.msg, tt.secret, now)
			if err != nil {
				t.Fatalf("encrypt error: %s", err)
			}
			msg, err := Decrypt(tok, tt.secret, now, time.Minute)
			if err != nil {
				t.Fatalf("decrypt error: %s", err)
			}
			if msg != tt.msg {
				t.Fatalf("wrong message: got %q, want %q", msg, tt.msg)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	var tests = []struct {
		msg, secret, token string
		ts                 int64
	}{
		{msg: "\"Zm\"N#\"AdVvUkfv:7\\n>&qDQ@r62IW4.A7h?+Yd.WPq;@", secret: "-hL5KvvgD4UI0Og7q5z4zr9C4l6LFOr8gerg0A8sreQ=", token: "gAAAAABZuWCeoWtiM_3OVcwX9WMyjeaRGCOAsxZvGPPJNr0XieK57DEbnmA4hA2iB4XU797FzrWSFJsQYY4wAFSWuvkFunDI5SC05KHcRrLmBSwV9YQppb4hZF_a0WKN__X5wRvIL6of", ts: 1505321118},
		{msg: "&6+{]52^C]htVc7--T9('?R.6y9>p.i%", secret: "r0v-RiQLxDG6csS2VMhwxGiiIdQSlcul3a0Wd3dm2pY=", token: "gAAAAABZuWCeLGUsTGZtIfJouxnQa1Rl1U6qxI_dlMUQtg2CTbHjV00_twnBppylqgzSPRXi2z9OdwfXGV5TzV3iVHu-wKgKvTHYA-jDYJwSGBHmXAvn6JTtIhjTQav6A5GmCAJlcGXV", ts: 1505321118},
		{msg: ",I", secret: "_1FNwDlG6784ln4r-qIJ6p-UxHYOXkO8CQksholcysw=", token: "gAAAAABZuWCe6nRdXH2WZhNU4HWF_mhI4tUnBx1_ytlA_W1ffia4dw16PXaNcXk1YTv4egd1qag5hTmW3-Y-O3sbG2bz2HagLg==", ts: 1505321118},
		{msg: "!vi;\\,VMz.UulgDHLl:u,)[[*2p>ORyOV?EADmwKHU($xMhR\"RsT^)wWJtQ0R2Y]JI[LaH7(9A\"Y},pxn_Jz", secret: "abM8U0U1wAk-BCa9q8xWxKR3pB-WhqxKRpvsKnAuUXo=", token: "gAAAAABZuWCeBMklvDdRHHyg6fOBNoDo_a_LfIQao2iLWnPcl519DGAHDyeas8m2MCOoq2WJ8OBl91xTOT5Wj91RrMLN06nynSCcvzeDMYUYgFt9Zi-Pp-ZASLBfP6q0LkRCOEnaMKa8IOfR6XBVk1bHvRX7ybQFp9Qdu5Q1xSUhBlTl6Bd9MG9YSOciRq2-Tsj9KycDKic2", ts: 1505321118},
		{msg: "%M#|)-j<hD`HL'WkW58xw\"6X:Kby{VsYC iya<wgtO", secret: "w1f4DCxc1uGJrKPZrA5rVQ-frSj8fTMmTaHUCz-zGvA=", token: "gAAAAABZuWCeFXkxyuhMUYhHOrm-b8k8DiEN1HPyzD9cplmERu5AoIYXRtpmbKxPA_A16Sbn-sc2RLT-DAEntsGnBA6CQ0h4mR1AMDhomRVeggXrpuEyJsB3O3s7mu6q9RE5RT8Jg5mX", ts: 1505321118},
		{msg: "|]Z.S?\\(|+W+U=4l.PN", secret: "klbyC8lbsvRiRRTUbxtYr2yXbyVP5D9J5JVYIgl7Mp8=", token: "gAAAAABZuWCemATfHQlpkVTaRHEkFr3fAYAq3VCFOlcrP4m__QP7eLPpn78Mu7s4pzietZp_vi51G6xoHuBqnGPhSUO68kgWHAbJt-VW71eQFJ5OM6N7inc=", ts: 1505321118},
		{msg: "5dH2@\"sI4Px<J7Cz.jcI5T},Id'", secret: "Ip-2pvPO4KT1YCMBELDVoirOxQXDCkFTsYj8cFqDUsk=", token: "gAAAAABZuWCe6yyMytAgnPu2ChOWF5juvOSnXLUsOUe8gaJQTAWuamrCPLcKgDved0fO93s8IiOqgZ6KIii883kp9S_xVtHvn4UMLuPje4Hl5I0tnH6XV94=", ts: 1505321118},
		{msg: "z>Lrvm>(!2NcDy}L`^SJMfJH#Tx\\i:&xwo,{( w\"cuhIj%6H0,tLr$m9=22ABPeooVwlw,[7}<ySKYd", secret: "0tVSNIYAA_eqQvorN0cY4WtQYJU7MWM-a1fUNxSd1XE=", token: "gAAAAABZuWCejwCocA_fn7VHeJRHOGGKd0JOwiWlBzonOLc7sl2_a6ypL-64ib9dEusOyPi3b8l6tJfK06j4yrebG5Bd1WO77QjzoUAh778zGnoB_vq9YFhKmr2RT2GSjDILPwajWP5JyOjmoZZ_9YdGOwv3Wju8T6bSu80iuOjQnceIA6INL1g=", ts: 1505321118},
		{msg: "8zS['=C]j={=c%Q?\"m\\wUb0+eH*E!&,P3iI2^8hznOaD8cDh,C", secret: "FoBIHfYDdZJYLp65msVVZd_BaE8hjLpna_dK_STxsh0=", token: "gAAAAABZuWCevkxhrKF7EDM7345urIus9zsDLXplVslCxKWic2X2qCVRXojKaQ9ALgxEH01WThaGJH_VIH7LO51NvsI4ZYS9PxkQFEji0cu_iV8Qy8JwTXE4UH4bV6RbAKPsD7NxzDtKJr4d_euOUrwgckn3yP1kHw==", ts: 1505321118},
		{msg: "=BBE\\%3>Yb#A,/LL0l9u;2W/=}Ns;v}EY1b*VX:Z\\qi)w_r|3b1Gs$B?f,]i1swfG(9\"6ApaZK8;S38pA 80wg-NH\\;U\"pEeWu", secret: "CMdiB4a1_nKWE8lMSUU5qgLV51UKbmOTSEYXNTWW3FU=", token: "gAAAAABZuWCe38QTCwZkOYTBnD_RZXRPaS8vjHbnHWPYNPdndkzcSCNQiY7QkSxekX3oVnZBnj9SzFI1qTc085VDM7OnpOIphDu8gu-ReOSlV6DvMDntmUnPRowkL2dZPxWqBM7QFNkEAB9mSQteTjVFjk_CVV3fobqpvlIwqH4hx4qBciATcp7Qw3XB1LuJiJcFsCdvdI29Jxpxj4G574_o8NR49RDawQ==", ts: 1505321118},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			msg, err := Decrypt(tt.token, tt.secret, time.Unix(tt.ts, 0), time.Minute)
			if err != nil {
				t.Fatalf("decrypt error: %s", err)
			}
			if msg != tt.msg {
				t.Fatalf("wrong message: got %q, want %q", msg, tt.msg)
			}
		})
	}
}
