from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import bcrypt
import base64
import os
import logging
import flask.cli

app = Flask(__name__)
app.secret_key = os.urandom(32)

def get_user_data(username):
    try:
        with open("bdd.txt", "r", encoding='utf-8') as file:
            for line in file:
                user, salt, stored_pass = line.strip().split(',', 2)
                if user == username:
                    return salt, stored_pass
    except FileNotFoundError:
        pass
    return None, None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].encode('utf-8')

        if not username or not password:
            flash("Tous les champs sont obligatoires", 'error')
            return redirect(url_for('index'))

        if 'register' in request.form:
            # Inscription
            if len(password) < 8:
                flash("Le mot de passe doit faire au moins 8 caractères", 'error')
                return redirect(url_for('index'))

            if get_user_data(username)[0]:
                flash("Cet utilisateur existe déjà", 'error')
                return redirect(url_for('index'))

            try:
                # Hashage et encryption
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(password, salt)
                
                # Envoi au serveur d'encryption
                response = requests.post(
                    "http://encryption:8000",
                    data={
                        'login': username,
                        'hashed_password': base64.b64encode(hashed).decode()
                    }
                )
                
                if response.status_code == 200:
                    # Sauvegarde
                    with open("bdd.txt", "a", encoding='utf-8') as f:
                        f.write(f"{username},{base64.b64encode(salt).decode()},{response.text}\n")
                    flash("Inscription réussie", 'success')
                else:
                    flash("Erreur lors de l'inscription", 'error')

            except Exception as e:
                print(f"Erreur: {str(e)}")
                flash("Erreur lors de l'inscription", 'error')

        elif 'login' in request.form:
            # Connexion
            salt, stored_pass = get_user_data(username)
            if not salt:
                flash("Utilisateur inconnu", 'error')
                return redirect(url_for('index'))

            try:
                # Vérification du mot de passe
                hashed = bcrypt.hashpw(password, base64.b64decode(salt))
                response = requests.post(
                    "http://encryption:8000",
                    data={
                        'login': username,
                        'hashed_password': base64.b64encode(hashed).decode()
                    }
                )

                if response.status_code == 200 and response.text.strip() == stored_pass.strip():
                    flash("Connexion réussie", 'success')
                else:
                    flash("Mot de passe incorrect", 'error')

            except Exception as e:
                print(f"Erreur: {str(e)}")
                flash("Erreur lors de la connexion", 'error')

        return redirect(url_for('index'))

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)