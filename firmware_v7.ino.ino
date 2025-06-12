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

// Variáveis para controle de tags
String ultimoUID = "";

void setup() {
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
}

void loop() {
  // Verifica se há um novo cartão presente
  if (!mfrc522.PICC_IsNewCardPresent()) {
    delay(50);
    return;
  }
  
  // Verifica se consegue ler o cartão
  if (!mfrc522.PICC_ReadCardSerial()) {
    delay(50);
    return;
  }
  
  // Gera o UID atual
  String uidAtual = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    uidAtual += String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
    uidAtual += String(mfrc522.uid.uidByte[i], HEX);
    if (i < mfrc522.uid.size - 1) uidAtual += ":";
  }
  uidAtual.toUpperCase();
  
  // Só processa se for uma nova tag
  if (uidAtual != ultimoUID) {
    ultimoUID = uidAtual;
    
    // Identifica o tipo da tag
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    
    // Procura por dados legíveis na tag
    String dadosEncontrados = "";
    
    // Tenta ler dados para diferentes tipos de tags
    if (piccType == MFRC522::PICC_TYPE_MIFARE_MINI ||
        piccType == MFRC522::PICC_TYPE_MIFARE_1K ||
        piccType == MFRC522::PICC_TYPE_MIFARE_4K) {
      
      dadosEncontrados = lerDadosMIFARE();
      
    } else if (piccType == MFRC522::PICC_TYPE_MIFARE_UL) {
      
      dadosEncontrados = lerDadosUltralight();
    }
    
    // Atualiza o LCD com os dados encontrados
    lcd.clear();
    
    if (dadosEncontrados.length() > 0) {
      // Remove espaços e caracteres inválidos
      dadosEncontrados.trim();
      
      lcd.setCursor(0, 0);
      lcd.print("Conteudo:");
      lcd.setCursor(0, 1);
      
      // Limita a 16 caracteres para caber no LCD
      if (dadosEncontrados.length() <= 16) {
        lcd.print(dadosEncontrados);
      } else {
        lcd.print(dadosEncontrados.substring(0, 16));
      }
    } else {
      // Se não encontrou dados legíveis, mostra o UID
      lcd.setCursor(0, 0);
      lcd.print("Tag ID:");
      lcd.setCursor(0, 1);
      
      String uidResumo = uidAtual;
      if (uidResumo.length() > 16) {
        uidResumo = uidResumo.substring(0, 16);
      }
      lcd.print(uidResumo);
    }
  }
  
  // Para a comunicação com o cartão
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  
  delay(200);
}

String lerDadosMIFARE() {
  MFRC522::MIFARE_Key key;
  String textoEncontrado = "";
  
  // Prepara a chave padrão
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }
  
  // Escaneia todos os setores procurando especificamente por texto (não URL)
  for (byte setor = 0; setor < 16 && textoEncontrado.length() == 0; setor++) {
    
    for (byte blocoRel = 0; blocoRel < 3; blocoRel++) { // 3 blocos por setor
      byte bloco = setor * 4 + blocoRel;
      
      // Pula o bloco 0 (dados do fabricante)
      if (bloco == 0) continue;
      if (bloco > 63) break; // MIFARE 1K limit
      
      // Tenta autenticar com chave A
      MFRC522::StatusCode status = mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, bloco, &key, &(mfrc522.uid)
      );
      
      if (status != MFRC522::STATUS_OK) {
        continue;
      }
      
      // Lê o bloco
      byte buffer[18];
      byte size = sizeof(buffer);
      status = mfrc522.MIFARE_Read(bloco, buffer, &size);
      
      if (status != MFRC522::STATUS_OK) {
        continue;
      }
      
      // Verifica se é um registro NDEF de texto (não URL)
      if (buffer[0] == 0x03) { // NDEF Message
        // Procura por registros de texto (Type T)
        for (byte i = 1; i < 15; i++) {
          if (buffer[i] == 0x54) { // Text Record Type 'T'
            // Encontrou registro de texto, extrai o conteúdo
            String textoBloco = extrairTextoNDEF(buffer, 16, i);
            if (textoBloco.length() > 0) {
              textoEncontrado = textoBloco;
              return textoEncontrado; // Retorna imediatamente quando encontrar texto
            }
          }
        }
      }
      
      // Se não é NDEF, verifica se é texto simples (fallback)
      if (textoEncontrado.length() == 0) {
        String textoBloco = "";
        int caracteresValidos = 0;
        bool temURL = false;
        
        for (byte i = 0; i < 16; i++) {
          if (buffer[i] == 0) {
            break;
          } else if (buffer[i] >= 32 && buffer[i] <= 126) {
            textoBloco += (char)buffer[i];
            caracteresValidos++;
            
            // Verifica se contém indicadores de URL
            if (textoBloco.indexOf("http") >= 0 || 
                textoBloco.indexOf("www.") >= 0 || 
                textoBloco.indexOf(".com") >= 0 ||
                textoBloco.indexOf(".br") >= 0) {
              temURL = true;
            }
          }
        }
        
        // Só aceita se for texto válido E não for URL
        if (caracteresValidos >= 2 && !temURL) {
          textoBloco.trim();
          if (textoBloco.length() > 0) {
            textoEncontrado = textoBloco;
          }
        }
      }
    }
  }
  
  return textoEncontrado;
}

String extrairTextoNDEF(byte* buffer, byte tamanho, byte posicao) {
  String texto = "";
  
  // NDEF Text Record format: [Header][Type Length][Payload Length][Type][Language][Text]
  if (posicao + 3 < tamanho) {
    byte payloadLength = buffer[posicao + 2]; // Tamanho do payload
    byte languageLength = buffer[posicao + 4] & 0x3F; // Tamanho do código de idioma
    
    // Pula header, type, e código de idioma para chegar ao texto
    byte inicioTexto = posicao + 4 + languageLength + 1;
    
    if (inicioTexto < tamanho) {
      for (byte i = inicioTexto; i < tamanho && i < inicioTexto + payloadLength - languageLength - 1; i++) {
        if (buffer[i] >= 32 && buffer[i] <= 126) {
          texto += (char)buffer[i];
        } else if (buffer[i] == 0) {
          break;
        }
      }
    }
  }
  
  return texto;
}

String lerDadosUltralight() {
  String textoEncontrado = "";
  
  // MIFARE Ultralight: lê páginas 4-15 (dados do usuário)
  for (byte pagina = 4; pagina < 16; pagina++) {
    byte buffer[18];
    byte size = sizeof(buffer);
    
    // Comando para ler página
    MFRC522::StatusCode status = mfrc522.MIFARE_Read(pagina, buffer, &size);
    
    if (status == MFRC522::STATUS_OK) {
      
      // Verifica se é um registro NDEF de texto
      if (buffer[0] == 0x03) { // NDEF Message
        // Procura por registros de texto (Type T)
        for (byte i = 1; i < 4; i++) {
          if (buffer[i] == 0x54) { // Text Record Type 'T'
            // Continua lendo páginas seguintes para pegar o texto completo
            String textoCompleto = lerTextoUltralightNDEF(pagina);
            if (textoCompleto.length() > 0) {
              return textoCompleto;
            }
          }
        }
      }
      
      // Se não é NDEF, verifica se é texto simples (mas não URL)
      String textoPagina = "";
      int caracteresValidos = 0;
      bool temURL = false;
      
      for (byte i = 0; i < 4; i++) { // Ultralight: 4 bytes por página
        if (buffer[i] == 0) {
          break;
        } else if (buffer[i] >= 32 && buffer[i] <= 126) {
          textoPagina += (char)buffer[i];
          caracteresValidos++;
        }
      }
      
      // Verifica se contém indicadores de URL
      if (textoPagina.indexOf("http") >= 0 || 
          textoPagina.indexOf("www.") >= 0 || 
          textoPagina.indexOf(".com") >= 0 ||
          textoPagina.indexOf(".br") >= 0) {
        temURL = true;
      }
      
      // Se encontrou texto válido e NÃO é URL, adiciona
      if (caracteresValidos > 0 && !temURL) {
        textoEncontrado += textoPagina;
      }
      
      // Se já tem texto suficiente e não é URL, para
      if (textoEncontrado.length() >= 4 && !temURL) {
        break;
      }
    }
  }
  
  return textoEncontrado;
}

String lerTextoUltralightNDEF(byte paginaInicial) {
  String textoCompleto = "";
  
  // Lê várias páginas para pegar o texto completo do NDEF
  for (byte pagina = paginaInicial; pagina < 16; pagina++) {
    byte buffer[18];
    byte size = sizeof(buffer);
    
    MFRC522::StatusCode status = mfrc522.MIFARE_Read(pagina, buffer, &size);
    
    if (status == MFRC522::STATUS_OK) {
      for (byte i = 0; i < 4; i++) {
        if (buffer[i] >= 32 && buffer[i] <= 126) {
          textoCompleto += (char)buffer[i];
        } else if (buffer[i] == 0 || buffer[i] == 0xFE) {
          // Fim do texto NDEF
          return textoCompleto;
        }
      }
    }
    
    // Se já tem texto suficiente, para
    if (textoCompleto.length() >= 16) {
      break;
    }
  }
  
  return textoCompleto;
}