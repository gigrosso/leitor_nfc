#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// Definição dos pinos para o RFID RC522
#define RST_PIN         9
#define SS_PIN          10

// Inicialização dos objetos
MFRC522 mfrc522(SS_PIN, RST_PIN);
LiquidCrystal_I2C lcd(0x27, 16, 2); // Endereço I2C 0x27, 16 colunas, 2 linhas

void setup() {
  Serial.begin(9600);
  
  // Inicializa o barramento SPI
  SPI.begin();
  
  // Inicializa o módulo RFID
  mfrc522.PCD_Init();
  
  // Inicializa o LCD
  lcd.init();
  lcd.backlight();
  lcd.clear();
  
  // Mensagem inicial no LCD
  lcd.setCursor(0, 0);
  lcd.print("Sistema RFID");
  lcd.setCursor(0, 1);
  lcd.print("Aproxime o tag");
  
  Serial.println("Sistema RFID iniciado");
  Serial.println("Aproxime um cartão ou tag...");
}

void loop() {
  // Verifica se há um novo cartão presente
  if (!mfrc522.PICC_IsNewCardPresent()) {
    return;
  }
  
  // Verifica se consegue ler o cartão
  if (!mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  
  // Limpa o LCD
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Tag detectado!");
  
  // Mostra o UID no LCD e Serial
  String uidString = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    uidString += String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
    uidString += String(mfrc522.uid.uidByte[i], HEX);
    if (i < mfrc522.uid.size - 1) uidString += ":";
  }
  uidString.toUpperCase();
  
  // Exibe o UID no LCD (linha 2)
  lcd.setCursor(0, 1);
  if (uidString.length() <= 16) {
    lcd.print(uidString);
  } else {
    // Se o UID for muito longo, mostra os primeiros 16 caracteres
    lcd.print(uidString.substring(0, 16));
  }
  
  // Mostra informações no Serial Monitor
  Serial.println("=== TAG DETECTADO ===");
  Serial.print("UID: ");
  Serial.println(uidString);
  Serial.print("Tipo: ");
  
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  String tipoCartao = mfrc522.PICC_GetTypeName(piccType);
  Serial.println(tipoCartao);
  
  // Tenta ler dados dos blocos (para tags MIFARE Classic)
  if (piccType == MFRC522::PICC_TYPE_MIFARE_MINI ||
      piccType == MFRC522::PICC_TYPE_MIFARE_1K ||
      piccType == MFRC522::PICC_TYPE_MIFARE_4K) {
    
    lerDadosCartao();
  }
  
  // Para a comunicação com o cartão
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  
  delay(2000); // Aguarda 2 segundos antes de procurar outro cartão
  
  // Retorna à mensagem inicial
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Sistema RFID");
  lcd.setCursor(0, 1);
  lcd.print("Aproxime o tag");
}

void lerDadosCartao() {
  MFRC522::MIFARE_Key key;
  
  // Prepara a chave - usando a chave padrão FFFFFFFFFFFFh
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }
  
  Serial.println("\n=== DADOS DO CARTÃO ===");
  
  // Lê alguns blocos de dados
  for (byte setor = 0; setor < 16; setor++) {
    for (byte bloco = 0; bloco < 4; bloco++) {
      byte blocoAtual = setor * 4 + bloco;
      
      // Pula blocos de trailer (múltiplos de 4, exceto 0)
      if (blocoAtual % 4 == 3 && blocoAtual != 0) continue;
      if (blocoAtual > 63) break; // MIFARE 1K tem 64 blocos (0-63)
      
      // Tenta autenticar
      MFRC522::StatusCode status = mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, blocoAtual, &key, &(mfrc522.uid)
      );
      
      if (status == MFRC522::STATUS_OK) {
        // Lê o bloco
        byte buffer[18];
        byte size = sizeof(buffer);
        
        status = mfrc522.MIFARE_Read(blocoAtual, buffer, &size);
        
        if (status == MFRC522::STATUS_OK) {
          Serial.print("Bloco ");
          Serial.print(blocoAtual);
          Serial.print(": ");
          
          // Mostra dados em HEX
          for (byte i = 0; i < 16; i++) {
            if (buffer[i] < 0x10) Serial.print("0");
            Serial.print(buffer[i], HEX);
            Serial.print(" ");
          }
          
          Serial.print(" | ASCII: ");
          // Mostra dados como texto (caracteres imprimíveis)
          String textoBloco = "";
          for (byte i = 0; i < 16; i++) {
            if (buffer[i] >= 32 && buffer[i] <= 126) {
              textoBloco += (char)buffer[i];
            } else {
              textoBloco += ".";
            }
          }
          Serial.println(textoBloco);
          
          // Se encontrou texto legível no bloco, mostra no LCD
          if (temTextoLegivel(buffer, 16) && blocoAtual > 0) {
            delay(1000);
            lcd.clear();
            lcd.setCursor(0, 0);
            lcd.print("Bloco ");
            lcd.print(blocoAtual);
            lcd.print(":");
            lcd.setCursor(0, 1);
            
            String textoLimpo = "";
            for (byte i = 0; i < 16 && textoLimpo.length() < 16; i++) {
              if (buffer[i] >= 32 && buffer[i] <= 126) {
                textoLimpo += (char)buffer[i];
              }
            }
            lcd.print(textoLimpo);
            delay(2000);
          }
        }
      }
    }
  }
}

bool temTextoLegivel(byte* buffer, byte tamanho) {
  int caracteresLegiveis = 0;
  for (byte i = 0; i < tamanho; i++) {
    if (buffer[i] >= 32 && buffer[i] <= 126) {
      caracteresLegiveis++;
    }
  }
  // Considera legível se pelo menos 30% dos caracteres são imprimíveis
  return (caracteresLegiveis > tamanho * 0.3);
}