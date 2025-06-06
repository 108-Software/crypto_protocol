package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func isAdmin() bool {
	if runtime.GOOS == "windows" {
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	}
	return os.Geteuid() == 0
}

func runAsAdmin() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}

	cmd := exec.Command("powershell", "Start-Process", exe, "-Verb", "RunAs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	return err == nil
}

func generateAndSaveKey(keyPath string) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0600); err != nil {
		return nil, err
	}

	return key, nil
}

func generateAndSaveNonce(noncePath string) ([]byte, error) {
	nonce := make([]byte, BlockSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	if err := os.WriteFile(noncePath, []byte(hex.EncodeToString(nonce)), 0600); err != nil {
		return nil, err
	}

	return nonce, nil
}

func encryptFileMenu(isAdmin bool) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Введите путь к файлу для шифрования: ")
	inputPath, _ := reader.ReadString('\n')
	inputPath = filepath.Clean(inputPath[:len(inputPath)-2])

	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		fmt.Println("Ошибка: файл не существует!")
		return
	}

	fmt.Print("Введите путь для сохранения зашифрованного файла: ")
	outputPath, _ := reader.ReadString('\n')
	outputPath = filepath.Clean(outputPath[:len(outputPath)-2])

	if info, err := os.Stat(outputPath); err == nil && info.IsDir() {
		fmt.Println("Ошибка: нужно указать полный путь к файлу, а не директорию!")
		return
	}

	var key, nonce []byte
	var err error

	if isAdmin {
		key, err = generateAndSaveKey("secret_key.txt")
		if err != nil {
			fmt.Printf("Ошибка генерации ключа: %v\n", err)
			return
		}

		nonce, err = generateAndSaveNonce("secret_nonce.txt")
		if err != nil {
			fmt.Printf("Ошибка генерации nonce: %v\n", err)
			return
		}
	} else {
		key, err = ReadKeyFromFile("secret_key.txt")
		if err != nil {
			fmt.Printf("Ошибка чтения ключа: %v\n", err)
			return
		}

		nonce, err = ReadNonceFromFile("secret_nonce.txt")
		if err != nil {
			fmt.Printf("Ошибка чтения nonce: %v\n", err)
			return
		}
	}

	mgm, err := NewMGM(key, nonce)
	if err != nil {
		fmt.Printf("Ошибка инициализации MGM: %v\n", err)
		return
	}

	if err := mgm.EncryptFile(inputPath, outputPath); err != nil {
		fmt.Printf("Ошибка шифрования: %v\n", err)
		return
	}

	fmt.Println("Файл успешно зашифрован!")
	if isAdmin {
		fmt.Println("Новый ключ сохранен в secret_key.txt")
		fmt.Println("Новый nonce сохранен в secret_nonce.txt")
	}

	zeroize(key)
	zeroize(nonce)

}

func decryptFileMenu() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Введите путь к зашифрованному файлу: ")
	inputPath, _ := reader.ReadString('\n')
	inputPath = filepath.Clean(inputPath[:len(inputPath)-2])

	fmt.Print("Введите путь для сохранения расшифрованного файла: ")
	outputPath, _ := reader.ReadString('\n')
	outputPath = filepath.Clean(outputPath[:len(outputPath)-2])

	key, err := ReadKeyFromFile("secret_key.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения ключа: %v\n", err)
		return
	}

	nonce, err := ReadNonceFromFile("secret_nonce.txt")
	if err != nil {
		fmt.Printf("Ошибка чтения nonce: %v\n", err)
		return
	}

	mgm, err := NewMGM(key, nonce)
	if err != nil {
		fmt.Printf("Ошибка инициализации MGM: %v\n", err)
		return
	}

	if err := mgm.DecryptFile(inputPath, outputPath); err != nil {
		fmt.Printf("Ошибка расшифровки: %v\n", err)
		return
	}

	fmt.Println("Файл успешно расшифрован!")

	zeroize(key)
	zeroize(nonce)

}

func changeKey() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Введите новый ключ (64 hex символа) или оставьте пустым для генерации: ")
	keyInput, _ := reader.ReadString('\n')
	keyInput = strings.TrimSpace(keyInput[:len(keyInput)-2])

	var key []byte
	var err error

	if keyInput == "" {
		key, err = generateAndSaveKey("secret_key.txt")
		if err != nil {
			fmt.Printf("Ошибка генерации ключа: %v\n", err)
			return
		}
		fmt.Println("Новый ключ сгенерирован и сохранен")
	} else {
		if len(keyInput) != 64 {
			fmt.Println("Ключ должен быть 64 hex символа!")
			return
		}

		key, err = hex.DecodeString(keyInput)
		if err != nil {
			fmt.Println("Неверный формат ключа!")
			return
		}

		if err := os.WriteFile("secret_key.txt", []byte(keyInput), 0600); err != nil {
			fmt.Printf("Ошибка сохранения ключа: %v\n", err)
			return
		}
		fmt.Println("Ключ успешно изменен")
	}

	fmt.Printf("Текущий ключ: %x\n", key)

	zeroize(key)

}

func showAdminMenu() {
	for {
		fmt.Println("\n=== Меню администратора ===")
		fmt.Println("1. Зашифровать файл (с генерацией новых ключей)")
		fmt.Println("2. Изменить ключ шифрования")
		fmt.Println("3. Расшифровать файл")
		fmt.Println("0. Выход")
		fmt.Print("Выберите действие: ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			encryptFileMenu(true)
		case 2:
			changeKey()
		case 3:
			decryptFileMenu()
		case 0:
			return
		default:
			fmt.Println("Неверный выбор!")
		}
	}
}

func showUserMenu() {
	for {
		fmt.Println("\n=== Меню пользователя ===")
		fmt.Println("1. Зашифровать файл")
		fmt.Println("2. Расшифровать файл")
		fmt.Println("0. Выход")
		fmt.Print("Выберите действие: ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			encryptFileMenu(false)
		case 2:
			decryptFileMenu()
		case 0:
			return
		default:
			fmt.Println("Неверный выбор!")
		}
	}
}

func main() {
	if !isAdmin() {
		fmt.Println("Запрашиваем права администратора...")
		if runAsAdmin() {
			os.Exit(0)
		} else {
			fmt.Println("Тип учетной записи: User")
			showUserMenu()
			return
		}
	}

	fmt.Println("Тип учетной записи: Admin")
	showAdminMenu()
}
