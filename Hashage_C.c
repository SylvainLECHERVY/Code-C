#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define HASH_SIZE 64 // Taille du hash SHA-256 en hexadécimal

// Fonction pour hacher un mot de passe avec SHA-256
void hashPassword(const char* password, char* hash) {
    unsigned char tempHash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen(password));
    SHA256_Final(tempHash, &ctx);

    // Convertir le hash en une chaîne hexadécimale
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash + (i * 2), "%02x", tempHash[i]);
    }
    hash[HASH_SIZE] = '\0';
}

// Fonction pour vérifier si un mot de passe correspond à un hash donné
int verifyPassword(const char* password, const char* hash) {
    char testHash[HASH_SIZE + 1];
    hashPassword(password, testHash);
    return strcmp(hash, testHash) == 0;
}

int main() {
    char password[50];
    char hash[HASH_SIZE + 1];

    // Demander à l'utilisateur de saisir un mot de passe
    printf("Entrez votre mot de passe : ");
    scanf("%s", password);

    // Hacher le mot de passe
    hashPassword(password, hash);

    printf("Mot de passe haché : %s\n", hash);

    // Vérifier si un mot de passe correspond à un hash donné
    char testPassword[50];
    printf("Entrez le mot de passe à vérifier : ");
    scanf("%s", testPassword);
    if (verifyPassword(testPassword, hash)) {
        printf("Le mot de passe est valide.\n");
    } else {
        printf("Le mot de passe est invalide.\n");
    }

    return 0;
}
