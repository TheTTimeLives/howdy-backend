# Howdy Backend (TypeScript + Firestore)

This is a secure backend API for the Howdy Flutter app, built with TypeScript, Express, and Firebase Admin SDK. It handles user sign-up, matchmaking queueing, and secure Agora call token generation.

---

## 🚀 Features

- 🔐 Firebase Auth token verification middleware
- 📝 User sign-up and profile storage in Firestore
- 🎯 Matchmaking queue (`/enqueue`)
- 📞 Agora token generation for voice/video calls

---

## 🛠 Requirements

- Node.js ≥ 18.x
- Firebase project
- Firestore enabled
- Firebase Auth enabled (Email/Password)
- Agora project (App ID + App Certificate)

---

## 📦 Setup

### 1. Clone & install

```bash
git clone <this-repo>
cd howdy-backend
npm install
