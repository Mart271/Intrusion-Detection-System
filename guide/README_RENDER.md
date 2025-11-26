# Deploying to Render.com

## Quick Setup Steps

1. **Push your code to GitHub**
   - Make sure all files are committed
   - Push to your GitHub repository

2. **Create a new Web Service on Render**
   - Go to [render.com](https://render.com)
   - Click "New +" → "Web Service"
   - Connect your GitHub repository

3. **Configure the service:**
   - **Name**: Your app name (e.g., "ids-system")
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn main:app --bind 0.0.0.0:$PORT`

4. **Set Environment Variables** (in Render dashboard):
   ```
   FLASK_ENV=production
   IDS_HOST=0.0.0.0
   IDS_SECRET_KEY=<generate a random secret key>
   IDS_ADMIN_PASSWORD=<your admin password>
   IDS_ANALYST_PASSWORD=<your analyst password>
   IDS_USER_PASSWORD=<your user password>
   CORS_ORIGINS=https://your-app-name.onrender.com
   ```

5. **Deploy**
   - Click "Create Web Service"
   - Render will automatically build and deploy

## Important Notes

- Render automatically sets the `PORT` environment variable
- Your app must bind to `0.0.0.0` (already configured)
- Use `gunicorn` for production (already in requirements.txt)
- The app variable is exported at the end of `main.py` for Render

## Troubleshooting

**"Not Found" Error:**
- Make sure `startCommand` is: `gunicorn main:app --bind 0.0.0.0:$PORT`
- Check that `app = IDSApplication().app` is at the end of main.py
- Verify PORT environment variable is set (Render sets this automatically)

**CORS Errors:**
- Set `CORS_ORIGINS` to your Render URL: `https://your-app.onrender.com`
- Or set `FLASK_ENV=development` temporarily for testing

**Database Issues:**
- SQLite files persist on Render's disk
- For production, consider using PostgreSQL (Render offers free PostgreSQL)

## Testing Locally

Test with Gunicorn locally:
```bash
pip install gunicorn
gunicorn main:app --bind 0.0.0.0:5000
```

Then visit: `http://localhost:5000`

