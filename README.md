# SecurityLinter

**SecurityLinter** est une bibliothèque PHP conçue pour analyser votre projet à la recherche de failles de sécurité courantes, comme les vulnérabilités liées au XSS (Cross-Site Scripting), et pour appliquer des corrections automatiques.

---

## 🚀 Fonctionnalités

- 🔍 **Analyse de sécurité :** Scanne vos fichiers à la recherche de problèmes de sécurité potentiels.
- 🛠️ **Correction automatique :** Identifie et corrige les failles XSS en encapsulant les superglobales (`$_GET`, `$_POST`, etc.) dans une fonction de nettoyage.
- 🗂️ **Support de plusieurs fichiers et dossiers :** Peut analyser un fichier spécifique ou un dossier entier.
- ⚡ **Facilité d'utilisation :** Une API simple et intuitive.

---

## 🛠️ Installation

**Pré-requis :**
- PHP 8.0 ou supérieur
- Composer

### Étape 1 : Installer avec Composer

Vous pouvez ajouter ce package dans votre projet avec **Composer** :

```bash
composer require votre-utilisateur/security-linter
```

### Étape 2 : Autoload de Composer

Assurez-vous que votre projet utilise l'autoloader de Composer. Ajoutez cette ligne au fichier PHP principal si nécessaire :

```php
require_once 'vendor/autoload.php';
```

---

## 🔧 Utilisation

### 1. Analyse et rapport des problèmes

La méthode `scanAndReport` permet de scanner un fichier ou un dossier et de générer un rapport des problèmes de sécurité. 

```php
<?php

use SecurityLinter\Linter;

// Scanne un répertoire ou un fichier
$issues = Linter::scanAndReport('/chemin/vers/votre/projet');

if (!empty($issues)) {
    echo "Problèmes détectés :\n";
    print_r($issues);
} else {
    echo "Aucun problème détecté.\n";
}
```

### 2. Correction automatique des failles XSS dans un fichier

La méthode `autoFixXSS` identifie les parties vulnérables dans un fichier PHP et les corrige automatiquement.

```php
<?php

use SecurityLinter\Linter;

// Corrige automatiquement un fichier spécifique
Linter::autoFixXSS('/chemin/vers/votre/fichier.php');
```

Exemple **avant la correction** :

```php
<?php
$nom = $_POST['prenom'];
echo $nom;
```

Exemple **après la correction** :

```php
<?php
$nom = cleanXSSCustom($_POST['prenom']);
echo $nom;
```

---

## 📚 Documentation des Méthodes

### 1. `scanAndReport`

```php
public static function scanAndReport(string $path): array
```

**Description :**
- Scanne le fichier ou dossier spécifié pour détecter des problèmes de sécurité.
- Renvoie un tableau associatif contenant le chemin des fichiers en tant que clé et une liste des problèmes en tant que valeur.

**Paramètres :**
- `$path` *(string)* : Chemin du fichier/dossier à scanner.

**Retour :**
- Un tableau des problèmes détectés.

---

### 2. `autoFixXSS`

```php
public static function autoFixXSS(string $filePath): void
```

**Description :**
- Scanne le fichier spécifié et remplace automatiquement les superglobales vulnérables (`$_GET`, `$_POST`, etc.) par une encapsulation dans la fonction de nettoyage définie (par défaut : `cleanXSSCustom`).

**Paramètres :**
- `$filePath` *(string)* : Chemin du fichier à corriger.

**Retour :**
- Aucun. Modifie directement le fichier.

---

## 🤝 Contribution

Vous souhaitez contribuer ? Voici comment :

1. Clonez ce dépôt :

   ```bash
   git clone https://github.com/votre-utilisateur/security-linter.git
   ```

2. Installez les dépendances via Composer :

   ```bash
   composer install
   ```

3. Créez un nouveau **branch** pour votre contribution :

   ```bash
   git checkout -b ma-contribution
   ```

4. Envoyez une pull request lorsque vous avez terminé vos modifications !

---

## 📄 Licence

Ce projet est sous licence **MIT**.

---

## 🙋 Support

Si vous avez des questions ou des problèmes, n'hésitez pas à ouvrir un problème (**issue**) sur le [dépôt GitHub](https://github.com/GONCALVES-RODRIGUES-Alex-2326052/security-linter/issues).

---

## 🌟 Remerciements

Merci d'utiliser **SecurityLinter** ! 
