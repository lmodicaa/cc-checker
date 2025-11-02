# 🎤 Snoop Dogg Checker - Beta Cerrada

Sistema de verificación de tarjetas de crédito usando Stripe API.

## 🚀 Deploy en Render.com

### Paso 1: Preparar Repositorio GitHub

1. Inicializa Git (si no lo tienes):
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   ```

2. Crea un repositorio en GitHub y conéctalo:
   ```bash
   git remote add origin https://github.com/TU_USUARIO/TU_REPO.git
   git push -u origin main
   ```

### Paso 2: Deploy en Render

1. **Ir a [Render.com](https://render.com)** y crear cuenta/login

2. **Crear nuevo Web Service**:
   - Conectar repositorio de GitHub
   - Seleccionar tu repositorio

3. **Configuración**:
   - **Name**: `snoop-dogg-checker` (o el que prefieras)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT`
   - **Plan**: Free (o el que prefieras)

4. **Agregar PostgreSQL Database**:
   - En el dashboard de Render, crear nueva "PostgreSQL" database
   - **Name**: `snoop_dogg_checker_db`
   - Render te dará automáticamente la variable `DATABASE_URL`

5. **Variables de Entorno** (en Settings → Environment):
   ```
   SECRET_KEY=tu_secret_key_super_segura_aqui
   FLASK_DEBUG=False
   ```

   **NOTA**: `DATABASE_URL` se agrega automáticamente cuando conectas la base de datos PostgreSQL.

6. **Deploy**:
   - Click en "Create Web Service"
   - Render construirá y desplegará automáticamente
   - ✅ URL HTTPS lista: `https://snoop-dogg-checker.onrender.com`

### Paso 3: Configuración Inicial

1. **Acceder al Admin Panel**:
   - Ve a: `https://TU_URL.onrender.com/admin/login`
   - Password por defecto: `admin123` (cámbiala después)

2. **Configurar Stripe Keys**:
   - En Admin Panel → Configuración
   - Agrega tu `stripe_pk` (Public Key)
   - Agrega tu `stripe_sk` (Secret Key)
   - Configura límites y gates disponibles

3. **Generar Keys para Usuarios**:
   - En Admin Panel → Keys
   - Genera keys para tus usuarios beta
   - Cada key funciona solo en 1 dispositivo/IP

## 📁 Estructura del Proyecto

```
snoop-dogg-checker/
├── app.py               # Aplicación principal Flask
├── models.py            # Modelos de base de datos (SQLAlchemy)
├── requirements.txt     # Dependencias Python
├── Procfile             # Comando de inicio para Render
├── runtime.txt          # Versión de Python
├── .gitignore           # Archivos a ignorar en Git
└── templates/           # Plantillas HTML
    ├── admin_login.html
    ├── admin.html
    ├── checker_auth.html
    ├── checker.html
    └── maintenance.html
```

## 🔐 Seguridad

- ✅ Keys sensibles solo en variables de entorno
- ✅ Autenticación por key única por dispositivo/IP
- ✅ Rate limiting por usuario
- ✅ HTTPS obligatorio para Stripe Live keys

## 🗄️ Base de Datos

- **Local**: SQLite (`instance/snoop_dogg_checker.db`)
- **Producción**: PostgreSQL (automático en Render)

El código detecta automáticamente si está en producción o local.

## 📝 Notas

- Render puede tener "spin down" en el plan gratuito (se duerme después de 15 min sin uso)
- Para evitar spin down, puedes usar servicios como [UptimeRobot](https://uptimerobot.com) para hacer ping cada 5 minutos
- La base de datos PostgreSQL es persistente y no se borra

---

🎤 **Snoop Dogg Checker** - Beta Cerrada

