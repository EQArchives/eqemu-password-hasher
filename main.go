package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Matches EQEmu loginserver/encryption.h EncryptionMode enum
var modeOptions = []string{
	"1 - MD5",
	"2 - MD5 (password:username)",
	"3 - MD5 (username:password)",
	"4 - MD5 Triple",
	"5 - SHA1",
	"6 - SHA1 (password:username) [default without ENABLE_SECURITY]",
	"7 - SHA1 (username:password)",
	"8 - SHA1 Triple",
	"9 - SHA512",
	"10 - SHA512 (password:username)",
	"11 - SHA512 (username:password)",
	"12 - SHA512 Triple",
	"13 - Argon2 [default with ENABLE_SECURITY]",
	"14 - SCrypt",
}

// Modes that require a username
var modeNeedsUsername = map[int]bool{
	2: true, 3: true, 4: true,
	6: true, 7: true, 8: true,
	10: true, 11: true, 12: true,
}

// --- Hash functions matching loginserver/encryption.cpp ---

func hashMD5(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func hashSHA1(s string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(s)))
}

func hashSHA512(s string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(s)))
}

// Argon2id matching libsodium crypto_pwhash_str with INTERACTIVE parameters.
// Output is the standard PHC string format that libsodium produces.
func hashArgon2(password string) (string, error) {
	salt := make([]byte, 16) // crypto_pwhash_SALTBYTES
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// crypto_pwhash_OPSLIMIT_INTERACTIVE = 2
	// crypto_pwhash_MEMLIMIT_INTERACTIVE = 67108864 bytes = 65536 KiB
	timeCost := uint32(2)
	memoryCost := uint32(65536) // KiB
	threads := uint8(1)
	keyLen := uint32(32)

	hash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, threads, keyLen)

	// PHC string format (matches libsodium output)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memoryCost, timeCost, threads, b64Salt, b64Hash), nil
}

// Custom base64 alphabet used by libsodium's escrypt (scrypt MCF format).
const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// encode64Uint32 encodes a value as little-endian custom base64, matching
// libsodium's escrypt encode64_uint32 function.
func encode64Uint32(value uint32, bits int) string {
	var result []byte
	for i := 0; i < bits; i += 6 {
		result = append(result, itoa64[value&0x3f])
		value >>= 6
	}
	return string(result)
}

// encode64Bytes encodes raw bytes in the escrypt custom base64 format,
// matching libsodium's escrypt encode64 function.
func encode64Bytes(src []byte) string {
	var result []byte
	i := 0
	for i+3 <= len(src) {
		v := uint(src[i]) | uint(src[i+1])<<8 | uint(src[i+2])<<16
		result = append(result, itoa64[v&0x3f])
		result = append(result, itoa64[(v>>6)&0x3f])
		result = append(result, itoa64[(v>>12)&0x3f])
		result = append(result, itoa64[(v>>18)&0x3f])
		i += 3
	}
	remaining := len(src) - i
	if remaining == 1 {
		v := uint(src[i])
		result = append(result, itoa64[v&0x3f])
		result = append(result, itoa64[(v>>6)&0x3f])
	} else if remaining == 2 {
		v := uint(src[i]) | uint(src[i+1])<<8
		result = append(result, itoa64[v&0x3f])
		result = append(result, itoa64[(v>>6)&0x3f])
		result = append(result, itoa64[(v>>12)&0x3f])
	}
	return string(result)
}

// SCrypt matching libsodium crypto_pwhash_scryptsalsa208sha256_str with
// INTERACTIVE parameters. Output is the escrypt $7$ MCF format.
//
// Key detail: escrypt passes the base64-ENCODED salt string (not the raw
// bytes) as the salt parameter to the scrypt KDF. This matches how
// libsodium's escrypt_r works internally.
func hashSCrypt(password string) (string, error) {
	rawSalt := make([]byte, 32)
	if _, err := rand.Read(rawSalt); err != nil {
		return "", err
	}

	// crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288
	// crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216
	// Translates to: N=16384, r=8, p=1
	N := 16384
	r := 8
	p := 1
	keyLen := 32

	// Encode salt to custom base64 first — escrypt uses the ENCODED salt
	// string as the PBKDF2 salt input, not the raw bytes.
	encodedSalt := encode64Bytes(rawSalt)

	dk, err := scrypt.Key([]byte(password), []byte(encodedSalt), N, r, p, keyLen)
	if err != nil {
		return "", err
	}

	// Build escrypt MCF format: $7$<log2N><r as 30-bit><p as 30-bit><salt_b64>$<hash_b64>
	log2N := uint32(14) // log2(16384)

	mcf := "$7$" +
		encode64Uint32(log2N, 6) +
		encode64Uint32(uint32(r), 30) +
		encode64Uint32(uint32(p), 30) +
		encodedSalt + "$" +
		encode64Bytes(dk)

	return mcf, nil
}

// verifySCrypt replicates libsodium's crypto_pwhash_scryptsalsa208sha256_str_verify
func verifySCrypt(storedHash, password string) bool {
	if len(storedHash) < 14 || storedHash[:3] != "$7$" {
		return false
	}
	lastDollar := strings.LastIndex(storedHash, "$")
	if lastDollar <= 3 {
		return false
	}
	encodedSalt := storedHash[14:lastDollar]
	expectedDK := storedHash[lastDollar+1:]

	dk, err := scrypt.Key([]byte(password), []byte(encodedSalt), 16384, 8, 1, 32)
	if err != nil {
		return false
	}
	return encode64Bytes(dk) == expectedDK
}

// eqcryptHash replicates loginserver/encryption.cpp eqcrypt_hash
func eqcryptHash(username, password string, mode int) (string, error) {
	switch mode {
	case 1:
		return hashMD5(password), nil
	case 2:
		return hashMD5(password + ":" + username), nil
	case 3:
		return hashMD5(username + ":" + password), nil
	case 4:
		return hashMD5(hashMD5(username) + hashMD5(password)), nil
	case 5:
		return hashSHA1(password), nil
	case 6:
		return hashSHA1(password + ":" + username), nil
	case 7:
		return hashSHA1(username + ":" + password), nil
	case 8:
		return hashSHA1(hashSHA1(username) + hashSHA1(password)), nil
	case 9:
		return hashSHA512(password), nil
	case 10:
		return hashSHA512(password + ":" + username), nil
	case 11:
		return hashSHA512(username + ":" + password), nil
	case 12:
		return hashSHA512(hashSHA512(username) + hashSHA512(password)), nil
	case 13:
		return hashArgon2(password)
	case 14:
		return hashSCrypt(password)
	default:
		return "", fmt.Errorf("unsupported encryption mode: %d", mode)
	}
}

func parseModeFromSelection(sel string) int {
	parts := strings.SplitN(sel, " ", 2)
	if len(parts) == 0 {
		return 0
	}
	mode, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return mode
}

func buildGenerateTab(w fyne.Window, statusLabel *widget.Label) *container.TabItem {
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username (required for some modes)")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")

	modeSelect := widget.NewSelect(modeOptions, nil)
	modeSelect.SetSelectedIndex(13) // Default: mode 14 - SCrypt

	usernameNote := widget.NewLabel("Username is not used for this mode")
	usernameNote.TextStyle = fyne.TextStyle{Italic: true}

	modeSelect.OnChanged = func(sel string) {
		mode := parseModeFromSelection(sel)
		if modeNeedsUsername[mode] {
			usernameNote.SetText("Username is required for this mode")
		} else {
			usernameNote.SetText("Username is not used for this mode")
		}
	}

	outputEntry := widget.NewEntry()
	outputEntry.SetPlaceHolder("Hash will appear here")

	hashButton := widget.NewButton("Generate Hash", func() {
		mode := parseModeFromSelection(modeSelect.Selected)
		if mode == 0 {
			statusLabel.SetText("Please select an encryption mode")
			return
		}

		password := passwordEntry.Text
		if password == "" {
			statusLabel.SetText("Password is required")
			return
		}

		username := usernameEntry.Text
		if modeNeedsUsername[mode] && username == "" {
			statusLabel.SetText("Username is required for this mode")
			return
		}

		hash, err := eqcryptHash(username, password, mode)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error: %v", err))
			outputEntry.SetText("")
			return
		}

		outputEntry.SetText(hash)
		statusLabel.SetText(fmt.Sprintf("Mode %d hash generated (%d chars)", mode, len(hash)))
	})
	hashButton.Importance = widget.HighImportance

	copyButton := widget.NewButton("Copy to Clipboard", func() {
		text := strings.TrimSpace(outputEntry.Text)
		if text != "" {
			w.Clipboard().SetContent(text)
			statusLabel.SetText(fmt.Sprintf("Copied to clipboard! (%d chars)", len(text)))
		}
	})

	content := container.NewVBox(
		widget.NewLabel("Encryption Mode:"),
		modeSelect,
		widget.NewLabel("Username:"),
		usernameEntry,
		usernameNote,
		widget.NewLabel("Password:"),
		passwordEntry,
		layout.NewSpacer(),
		hashButton,
		widget.NewSeparator(),
		widget.NewLabel("Hash Output (for login_accounts.account_password):"),
		outputEntry,
		container.NewHBox(copyButton, layout.NewSpacer()),
	)

	return container.NewTabItem("Generate", content)
}

func buildVerifyTab(w fyne.Window, statusLabel *widget.Label) *container.TabItem {
	hashEntry := widget.NewEntry()
	hashEntry.SetPlaceHolder("Paste hash from database here")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password to verify")

	resultLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	verifyButton := widget.NewButton("Verify", func() {
		hash := strings.TrimSpace(hashEntry.Text)
		password := passwordEntry.Text

		if hash == "" || password == "" {
			statusLabel.SetText("Both hash and password are required")
			return
		}

		statusLabel.SetText(fmt.Sprintf("Hash length: %d chars", len(hash)))

		if strings.HasPrefix(hash, "$7$") {
			if verifySCrypt(hash, password) {
				resultLabel.SetText("PASS - Password matches this SCrypt hash")
			} else {
				resultLabel.SetText("FAIL - Password does NOT match this SCrypt hash")
			}
		} else if strings.HasPrefix(hash, "$argon2") {
			resultLabel.SetText("Argon2 verification not yet supported in verify tab")
		} else {
			resultLabel.SetText(fmt.Sprintf("Hash is %d chars (MD5=32, SHA1=40, SHA512=128) - use Generate tab to compare", len(hash)))
		}
	})
	verifyButton.Importance = widget.HighImportance

	pasteButton := widget.NewButton("Paste from Clipboard", func() {
		text := w.Clipboard().Content()
		hashEntry.SetText(strings.TrimSpace(text))
		statusLabel.SetText(fmt.Sprintf("Pasted %d chars (trimmed whitespace)", len(strings.TrimSpace(text))))
	})

	content := container.NewVBox(
		widget.NewLabel("Paste the hash from your database:"),
		hashEntry,
		container.NewHBox(pasteButton, layout.NewSpacer()),
		widget.NewLabel("Password:"),
		passwordEntry,
		layout.NewSpacer(),
		verifyButton,
		widget.NewSeparator(),
		resultLabel,
	)

	return container.NewTabItem("Verify", content)
}

func main() {
	a := app.New()
	w := a.NewWindow("EQEmu Password Hasher")
	w.Resize(fyne.NewSize(700, 520))

	statusLabel := widget.NewLabel("")

	tabs := container.NewAppTabs(
		buildGenerateTab(w, statusLabel),
		buildVerifyTab(w, statusLabel),
	)

	content := container.NewBorder(
		widget.NewLabelWithStyle("EQEmu Login Account Password Hasher",
			fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		statusLabel,
		nil, nil,
		tabs,
	)

	w.SetContent(container.NewPadded(content))
	w.ShowAndRun()
}
