package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	KeySize        = 32 // 256 бит
	Iterations     = 10000
	SaltSize       = 16
	LabelMaxSize   = 64
	ContextMaxSize = 64
)

var (
	MasterKey      []byte
	CurrentLabel   string
	CurrentContext string
)

func init() {
	// Инициализация мастер-ключа (в реальной системе должен храниться в HSM)
	MasterKey = make([]byte, KeySize)
	if _, err := rand.Read(MasterKey); err != nil {
		panic(err)
	}
	CurrentLabel = "default_label"
	CurrentContext = "default_context"
}

// DeriveKey реализует алгоритм из Р 1323565.1.022-2018
func DeriveKey(masterKey []byte, label string, context string) []byte {
	// 1. Проверка входных параметров
	if len(label) > LabelMaxSize {
		label = label[:LabelMaxSize]
	}
	if len(context) > ContextMaxSize {
		context = context[:ContextMaxSize]
	}

	// 2. Формирование строки D
	D := fmt.Sprintf("%s||%s", label, context)

	// 3. Генерация соли
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	// 4. Выработка производного ключа
	dk := pbkdf2.Key(masterKey, []byte(D), Iterations, KeySize, sha256.New)

	// 5. Возврат производного ключа
	return dk
}

func GenerateNewKey() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Введите метку (label, макс 64 символа): ")
	label, _ := reader.ReadString('\n')
	label = strings.TrimSpace(label)

	fmt.Print("Введите контекст (context, макс 64 символа): ")
	context, _ := reader.ReadString('\n')
	context = strings.TrimSpace(context)

	derivedKey := DeriveKey(MasterKey, label, context)

	// Сохраняем параметры для последующего использования
	CurrentLabel = label
	CurrentContext = context

	// Сохраняем ключ в файл
	keyData := fmt.Sprintf("%s\n%s\n%s", hex.EncodeToString(derivedKey), label, context)
	if err := os.WriteFile("derived_key.txt", []byte(keyData), 0600); err != nil {
		return nil, err
	}

	return derivedKey, nil
}

func ShowCurrentKey() ([]byte, error) {
	data, err := os.ReadFile("derived_key.txt")
	if err != nil {
		return nil, err
	}

	parts := strings.Split(string(data), "\n")
	if len(parts) < 3 {
		return nil, fmt.Errorf("неверный формат файла ключа")
	}

	key, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	CurrentLabel = parts[1]
	CurrentContext = parts[2]

	return key, nil
}

func ChangeMasterKey() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Введите новый мастер-ключ (64 hex символа) или оставьте пустым для генерации: ")
	keyInput, _ := reader.ReadString('\n')
	keyInput = strings.TrimSpace(keyInput)

	var newKey []byte
	var err error

	if keyInput == "" {
		newKey = make([]byte, KeySize)
		if _, err = rand.Read(newKey); err != nil {
			return err
		}
		fmt.Println("Новый мастер-ключ сгенерирован")
	} else {
		if len(keyInput) != 64 {
			return fmt.Errorf("ключ должен быть 64 hex символа")
		}

		newKey, err = hex.DecodeString(keyInput)
		if err != nil {
			return err
		}
	}

	MasterKey = newKey
	fmt.Println("Мастер-ключ успешно изменен")
	return nil
}

func TestDerivation() {
	fmt.Println("\n=== Тестирование алгоритма диверсификации ===")

	// Тест 1: Проверка детерминированности
	key1 := DeriveKey(MasterKey, "test_label", "test_context")
	key2 := DeriveKey(MasterKey, "test_label", "test_context")

	fmt.Printf("Ключ 1: %x\n", key1)
	fmt.Printf("Ключ 2: %x\n", key2)

	if equalKeys(key1, key2) {
		fmt.Println("Тест 1 пройден: одинаковые параметры дают одинаковый ключ")
	} else {
		fmt.Println("Тест 1 не пройден")
	}

	// Тест 2: Проверка уникальности при разных параметрах
	key3 := DeriveKey(MasterKey, "test_label2", "test_context2")
	fmt.Printf("Ключ 3: %x\n", key3)

	if !equalKeys(key1, key3) {
		fmt.Println("Тест 2 пройден: разные параметры дают разные ключи")
	} else {
		fmt.Println("Тест 2 не пройден")
	}

	// Тест 3: Проверка длины ключа
	if len(key1) == KeySize {
		fmt.Println("Тест 3 пройден: длина ключа корректна")
	} else {
		fmt.Println("Тест 3 не пройден")
	}
}

func equalKeys(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func ShowMenu() {
	for {
		fmt.Println("\n=== Меню диверсификации ключей (Р 1323565.1.022-2018) ===")
		fmt.Println("1. Сгенерировать новый производный ключ")
		fmt.Println("2. Показать текущий производный ключ")
		fmt.Println("3. Изменить мастер-ключ")
		fmt.Println("4. Протестировать алгоритм")
		fmt.Println("5. Показать текущие параметры")
		fmt.Println("0. Выход")
		fmt.Print("Выберите действие: ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			key, err := GenerateNewKey()
			if err != nil {
				fmt.Printf("Ошибка: %v\n", err)
			} else {
				fmt.Printf("Новый производный ключ: %x\n", key)
				fmt.Printf("Метка: %s\n", CurrentLabel)
				fmt.Printf("Контекст: %s\n", CurrentContext)
			}
		case 2:
			key, err := ShowCurrentKey()
			if err != nil {
				fmt.Printf("Ошибка: %v\n", err)
			} else {
				fmt.Printf("Текущий производный ключ: %x\n", key)
				fmt.Printf("Метка: %s\n", CurrentLabel)
				fmt.Printf("Контекст: %s\n", CurrentContext)
			}
		case 3:
			if err := ChangeMasterKey(); err != nil {
				fmt.Printf("Ошибка: %v\n", err)
			}
		case 4:
			TestDerivation()
		case 5:
			fmt.Printf("Текущая метка: %s\n", CurrentLabel)
			fmt.Printf("Текущий контекст: %s\n", CurrentContext)
		case 0:
			return
		default:
			fmt.Println("Неверный выбор!")
		}
	}
}

func main() {
	fmt.Println("Программа диверсификации ключей по Р 1323565.1.022-2018")
	ShowMenu()
}
