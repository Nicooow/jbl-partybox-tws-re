# Décompilation complète avec Ghidra (WSL) + exploration VSCode

Le firmware du module Bluetooth (`payload_1.bin`, 3,1 Mo — ARM Cortex-M, XIP @ 0x3C000000)
et celui du MCU panneau avant (`payload_4.bin`, 47 Ko — Cortex-M0 @ 0x08002000) sont du
code ARM Thumb en clair. Ce kit les rend entièrement décompilables en C, explorables
dans VSCode.

## 1. Préparation WSL (une fois)

```bash
sudo apt install -y openjdk-21-jdk unzip python3 git
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250612.zip -O ghidra.zip
unzip ghidra.zip -d ~/ghidra
echo 'export GHIDRA_INSTALL_DIR=~/ghidra/ghidra_11.4.2_PUBLIC' >> ~/.bashrc
source ~/.bashrc
```

## 2. Fabriquer les ELF

```bash
python3 make_elf.py payload_1.bin 3C000000 payload1.elf
python3 make_elf.py payload_4.bin 08002000 payload4.elf
```

## 3. Analyse + décompilation complète (headless)

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/proj JBL \
    -import payload1.elf -processor ARM:LE:32:Cortex \
    -scriptPath . -postScript DecompileAll.py /tmp/decomp_p1
```
(prise de 10 à 40 min sur le payload_1 — c'est 3 Mo. Refaire pareil avec `payload4.elf`
→ quelques minutes.)

Puis dans VSCode **Windows** : `File > Open Folder` → `\\wsl$\Ubuntu\tmp\decomp_p1`
(le système de fichiers WSL est visible nativement). Chaque fonction = un fichier `.c`
décompilé, avec un `_index.txt` trié par adresse. Recherche globale Ctrl+Shift+F
fonctionne sur tout le corpus.

## 4. Astuces d'exploration

- Chercher `TWS_BESAUD`, `SOURCE=%d`, `STANDBY=%d`, `0xbe59` pour retomber sur les
  fonctions qu'on a déjà identifiées (les adresses du README sont valables :
  `parse_cmd` @ 0x3C01A1F4, dispatcher RX @ 0x3C01A8A8, `build_cmd` @ 0x3C012EA4…).
- La décompilation Ghidra est bonne sur ce binaire (Cortex-M4, -O2) : les 17 handlers
  BESAUD seront lisibles directement.
- Pour le payload_0 du SPHE (ARM9, encodé) : ce kit ne sert à rien tant que
  l'encodage n'est pas cassé — et si le dump NOR arrive un jour, l'import Ghidra sera
  `ARM:LE:32:ARMv5` base 0x0 (à ajuster).

## 5. REA sous WSL ?

Le MCP REA tourne côté Windows et son pont Ghidra Windows n'accepte que des PE x86/x64.
Deux options :
- **Lancer la session ZCode depuis WSL** : REA tournera alors côté Linux, où son
  provider Ghidra accepte les ELF ARM (`GHIDRA_INSTALL_DIR` du WSL) — et on pourra
  lui demander des décompilations à la demande dans la conversation ;
- ou utiliser ce kit headless (suffisant pour tout explorer hors ligne).
