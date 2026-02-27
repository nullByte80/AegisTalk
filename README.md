# AegisTalk - Secure Encrypted Chat

AegisTalk is a decentralized, peer-to-peer (P2P) chat application developed for a Cryptography course project. focusing on hybrid modern encryption techniques.

---

##  Security Features

* **Hybrid Encryption**: Combines AES-256 and ChaCha20 for message confidentiality.
* **Key Exchange**: Uses the Diffie-Hellman (DH) protocol for secure shared secret generation.
* **P2P Architecture**: No central server; direct connection between Owner and Guest.


---

##  Getting Started

Follow these instructions to set up the project on your local machine.

### Prerequisites

* Python 3.8 or higher installed.
* Git installed.

---

## 📦 Installation & Setup

### 1️- Clone the Repository

```bash
git clone https://github.com/m0stafaSec/AegisTalk.git
cd AegisTalk-P2P
```

### 2️- Create a Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv

# Linux/macOS
python3 -m venv venv
```

### 3️- Activate the Virtual Environment

```bash
# Windows
.\venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 4️- Install Required Libraries

```bash
pip install -r requirements.txt
```

---

##  Usage

To start the application, run the following command from the project root directory:

```bash
python main.py
```

* Choose **Option 1** to create a secure room as the **Owner**.
* Choose **Option 2** to join an existing room as a **Guest** (using the Owner's IP address).

---

## 🛠 Project Scenario

This project adheres to **Scenario 2** of the Cryptography Project requirements:

* Implementation of two modern encryption algorithms (**AES** & **ChaCha20**).
* Performance comparison between standalone and hybrid techniques.
* Hybridization by using the output of one technique as input to another.

---

##  Credits

Developed by a team of six members:

* Mostafa Shaaban
* Abdullah El-Shehaly
* Fares Ashraf
* Youssef Ibrahim
* Islam Ayman
