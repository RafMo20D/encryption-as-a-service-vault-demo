# Go Encryption-as-a-Service with HashiCorp Vault

This repository contains a simple Go-based Encryption-as-a-Service (EaaS) application using HashiCorp Vault's Transit Secrets Engine.

## Prerequisites

1. **HashiCorp Vault:**
   - Install and configure HashiCorp Vault. Refer to the [Vault Installation Guide](https://learn.hashicorp.com/tutorials/vault/getting-started-install) for instructions.

2. **Go:**
   - Install Go on your machine. Refer to the [Official Go Documentation](https://golang.org/doc/install) for installation instructions.

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/RafMo20D/encryption-as-a-Service-vault.git
cd encryption-as-a-Service-vault
```

### 2. Install Dependencies

```bash
go get github.com/hashicorp/vault/api
```
### 3. Configure Vault
. Enable the Transit Secrets Engine:

```bash
vault secrets enable transit
```

. Create a named encryption key (replace my-key with your desired key name):

```bash
vault write -f transit/keys/my-key
```
### 4. Run the Go EaaS Server

1. Run the Application

```bash 
go run main.go
```
The server will start and listen on http://localhost:8080.

2. Endpoints
 . /encrypt: POST request with plaintext parameter.
 . /decrypt: POST request with ciphertext parameter.
 
 ### Example usage:

```bash
curl -X POST -d "plaintext=HelloWorld" http://localhost:8080/encrypt
```
### Troubleshooting

If you encounter permission issues, ensure that your Vault token has the necessary policies and permissions. Create  a policy file and associate it with your token.

### Contributions

Contributions are welcome! Feel free to open issues, provide feedback, or submit pull requests.
