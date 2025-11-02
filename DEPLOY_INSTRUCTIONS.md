# 🚀 Instrucciones de Deploy a Render

## Paso 1: Preparar Git

```bash
git init
git add .
git commit -m "Initial commit - Snoop Dogg Checker"
```

## Paso 2: Subir a GitHub

1. Crea un nuevo repositorio en [GitHub.com](https://github.com/new)
2. **NO** inicialices con README (ya tienes uno)
3. Copia la URL del repo (ejemplo: `https://github.com/tu-usuario/snoop-dogg-checker.git`)

```bash
git remote add origin https://github.com/TU_USUARIO/TU_REPO.git
git branch -M main
git push -u origin main
```

## Paso 3: Deploy en Render

### 3.1 Crear Web Service

1. Ve a [render.com](https://render.com) y haz login
2. Click en **"New +"** → **"Web Service"**
3. Conecta tu repositorio de GitHub
4. Selecciona tu repo `snoop-dogg-checker`

### 3.2 Configuración del Web Service

- **Name**: `snoop-dogg-checker` (o el que prefieras)
- **Environment**: `Python 3`
- **Region**: Oregon (US West) o el más cercano
- **Branch**: `main`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn beta_app:app --bind 0.0.0.0:$PORT`
- **Instance Type**: Free (o el que prefieras)

### 3.3 Variables de Entorno

Click en **"Advanced"** → **"Add Environment Variable"**:

```
SECRET_KEY = genera_una_clave_segura_aqui
FLASK_DEBUG = False
```

**Para generar SECRET_KEY segura:**
```python
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3.4 Agregar PostgreSQL

1. En el dashboard de Render, click en **"New +"** → **"PostgreSQL"**
2. **Name**: `snoop-dogg-checker-db`
3. **Database**: `snoop_dogg_checker`
4. **User**: (automático)
5. **Region**: El mismo que tu web service
6. **PostgreSQL Version**: 15 (última estable)
7. **Instance Type**: Free

### 3.5 Conectar Database al Web Service

1. Ve a tu Web Service
2. **Environment** → **"Add Environment Variable"**
3. Click en **"Add from Database"**
4. Selecciona tu database `snoop-dogg-checker-db`
5. Selecciona **"Internal Database URL"**
6. Render agregará automáticamente `DATABASE_URL`

### 3.6 Deploy

1. Click en **"Create Web Service"**
2. Render automáticamente:
   - Clonará tu repositorio
   - Instalará dependencias
   - Creará las tablas de la base de datos
   - Iniciará tu aplicación
3. Espera 2-3 minutos
4. ✅ Tu app estará en: `https://snoop-dogg-checker.onrender.com`

## Paso 4: Configuración Inicial Post-Deploy

### 4.1 Acceder al Admin Panel

1. Ve a: `https://TU_APP.onrender.com/admin/login`
2. Password por defecto: `admin123`
3. ⚠️ **IMPORTANTE**: Cámbiala inmediatamente

### 4.2 Configurar Stripe Keys

En el Admin Panel:
1. Click en **"Configuración"**
2. Agregar `stripe_pk` (Public Key de Stripe)
3. Agregar `stripe_sk` (Secret Key de Stripe)
4. Configurar `max_checks_per_day` (ejemplo: 20)
5. Guardar cambios

### 4.3 Generar Keys para Usuarios

1. En Admin Panel → **"Keys"**
2. Click en **"Generar Nueva Key"**
3. Ingresa nombre del usuario
4. Copia la key generada
5. Envía la key al usuario beta

## Paso 5: Mantener la App Activa (Opcional)

Render Free tier duerme la app después de 15 minutos sin uso.

**Solución**: Usa [UptimeRobot](https://uptimerobot.com) (gratis)
1. Crea cuenta en UptimeRobot
2. Agrega un monitor HTTP(s)
3. URL: `https://TU_APP.onrender.com`
4. Intervalo: Cada 5 minutos
5. ✅ Tu app se mantendrá activa 24/7

## 🔍 Verificación

- [ ] App responde en la URL de Render
- [ ] Admin login funciona
- [ ] Configuración de Stripe guardada correctamente
- [ ] Keys generadas funcionan
- [ ] Verificación de tarjetas funciona
- [ ] HTTPS activo (automático en Render)

## 🐛 Troubleshooting

### Error: "Application failed to respond"
- Revisa los logs en Render: **Logs** tab
- Verifica que `DATABASE_URL` esté configurada
- Asegúrate de que las dependencias se instalaron correctamente

### Error: "Cannot connect to database"
- Verifica que agregaste la database al web service
- Usa "Internal Database URL" (más rápido y gratis)
- Espera 1-2 minutos después de crear la database

### La app tarda mucho en responder
- Primera carga después de inactividad toma ~30-60 segundos (spin up)
- Considera usar UptimeRobot para mantenerla activa

## 📝 Notas Importantes

- ✅ HTTPS es automático en Render
- ✅ PostgreSQL Free tier: 1GB de almacenamiento
- ✅ Web Service Free tier: 750 horas/mes (suficiente para 1 app)
- ✅ Auto-deploys: Cada push a `main` redeploya automáticamente
- ✅ Variables de entorno son privadas y seguras

---

🎤 **Snoop Dogg Checker** - Ready for Production!

