from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Tournament, Team, Match
import os
import math
import random
from datetime import datetime
from flask_migrate import Migrate

# After db initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tournament.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

migrate = Migrate(app, db)
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    tournaments = Tournament.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, tournaments=tournaments)

@app.route('/create', methods=['GET', 'POST'])
def create_tournament():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Validate required fields
            if not request.form.get('name'):
                flash('Tournament name is required', 'error')
                return redirect(url_for('create_tournament'))
            
            mode = request.form.get('mode')
            if not mode or mode not in ['single_elimination', 'double_elimination', 'round_robin']:
                flash('Please select a valid tournament mode', 'error')
                return redirect(url_for('create_tournament'))
            
            team_names = request.form.getlist('team_name')
            team_names = [name.strip() for name in team_names if name.strip()]
            
            if len(team_names) < 2:
                flash('You need at least 2 teams to create a tournament', 'error')
                return redirect(url_for('create_tournament'))
            
            # Create tournament
            tournament = Tournament(
                name=request.form['name'],
                mode=mode,
                user_id=session['user_id'],
                created_at=datetime.utcnow()
            )
            db.session.add(tournament)
            db.session.commit()
            
            # Create teams
            teams = []
            for team_name in team_names:
                team = Team(tournament_id=tournament.id, name=team_name)
                teams.append(team)
                db.session.add(team)
            db.session.commit()
            
            # Generate matches based on mode
            if mode == 'single_elimination':
                generate_initial_matches(tournament.id, teams, mode)
            elif mode == 'double_elimination':
                generate_double_elimination_matches(tournament.id, teams)
            elif mode == 'round_robin':
                generate_round_robin_matches(tournament.id, teams)
            
            flash('Tournament created successfully!', 'success')
            return redirect(url_for('view_bracket', tournament_id=tournament.id))
        
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('create_tournament'))
    
    return render_template('create.html')

def generate_initial_matches(tournament_id, teams, mode):
    if mode == 'single_elimination':
        # Shuffle teams for random seeding
        random.shuffle(teams)
        
        # Calculate number of rounds
        num_teams = len(teams)
        num_rounds = math.ceil(math.log2(num_teams))
        
        # Create first round matches
        for i in range(0, len(teams), 2):
            team1 = teams[i]
            team2 = teams[i+1] if i+1 < len(teams) else None
            
            match = Match(
                tournament_id=tournament_id,
                round_number=1,
                team1_id=team1.id,
                team2_id=team2.id if team2 else None,
                winner_id=None
            )
            db.session.add(match)
        
        db.session.commit()

@app.route('/bracket/<int:tournament_id>')
def view_bracket(tournament_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    tournament = Tournament.query.get_or_404(tournament_id)
    if tournament.user_id != session['user_id']:
        flash('You do not have permission to view this tournament', 'error')
        return redirect(url_for('dashboard'))
    
    teams = Team.query.filter_by(tournament_id=tournament_id).all()
    matches = Match.query.filter_by(tournament_id=tournament_id).all()
    
    if tournament.mode == 'round_robin':
        return render_template('bracket.html', 
                            tournament=tournament,
                            teams=teams,
                            matches=matches)
    
    # For elimination brackets
    max_round = 0
    if matches:
        max_round = max(m.round_number for m in matches)
    
    return render_template('bracket.html',
                         tournament=tournament,
                         teams=teams,
                         matches=matches,
                         max_round=max_round)
@app.route('/set_winner/<int:match_id>/<int:team_id>')
def set_winner(match_id, team_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    match = Match.query.get_or_404(match_id)
    tournament = Tournament.query.get_or_404(match.tournament_id)
    
    if tournament.user_id != session['user_id']:
        flash('You do not have permission to modify this tournament', 'error')
        return redirect(url_for('dashboard'))
    
    # Set winner
    match.winner_id = team_id
    db.session.commit()
    
    if tournament.mode == 'single_elimination':
        # Check if all matches in this round are complete
        current_round_matches = Match.query.filter_by(
            tournament_id=tournament.id,
            round_number=match.round_number
        ).all()
        
        all_matches_complete = all(m.winner_id is not None for m in current_round_matches)
        
        if all_matches_complete:
            # Generate next round if needed
            next_round = match.round_number + 1
            next_round_matches = Match.query.filter_by(
                tournament_id=tournament.id,
                round_number=next_round
            ).count()
            
            if next_round_matches == 0:
                # Need to create next round
                winners = [m.winner_id for m in current_round_matches]
                
                # If only one winner left, tournament is complete
                if len(winners) == 1:
                    flash(f'Tournament complete! Winner: {Team.query.get(winners[0]).name}', 'success')
                else:
                    # Create matches for next round
                    for i in range(0, len(winners), 2):
                        team1_id = winners[i]
                        team2_id = winners[i+1] if i+1 < len(winners) else None
                        
                        new_match = Match(
                            tournament_id=tournament.id,
                            round_number=next_round,
                            team1_id=team1_id,
                            team2_id=team2_id,
                            winner_id=None
                        )
                        db.session.add(new_match)
                    db.session.commit()
    
    elif tournament.mode == 'double_elimination':
        if match.bracket_type == 'grand_finals':
            flash(f'Tournament complete! Winner: {Team.query.get(team_id).name}', 'success')
        else:
            advance_double_elimination(tournament.id, match.round_number, match.bracket_type)
    
    return redirect(url_for('view_bracket', tournament_id=tournament.id))
def generate_double_elimination_matches(tournament_id, teams):
    # Shuffle teams for random seeding
    random.shuffle(teams)
    
    # Winners bracket matches
    winners_round1 = []
    for i in range(0, len(teams), 2):
        team1 = teams[i]
        team2 = teams[i+1] if i+1 < len(teams) else None
        
        match = Match(
            tournament_id=tournament_id,
            round_number=1,
            bracket_type='winners',
            team1_id=team1.id,
            team2_id=team2.id if team2 else None,
            winner_id=None
        )
        db.session.add(match)
        winners_round1.append(match)
    
    db.session.commit()
    return winners_round1

def generate_round_robin_matches(tournament_id, teams):
    matches = []
    # Generate all possible unique pairings
    for i in range(len(teams)):
        for j in range(i+1, len(teams)):
            match = Match(
                tournament_id=tournament_id,
                round_number=1,  # All matches in single round for RR
                bracket_type='round_robin',
                team1_id=teams[i].id,
                team2_id=teams[j].id,
                winner_id=None
            )
            db.session.add(match)
            matches.append(match)
    
    db.session.commit()
    return matches

def advance_double_elimination(tournament_id, current_round, bracket_type):
    # Get all matches from current round in this bracket
    current_matches = Match.query.filter_by(
        tournament_id=tournament_id,
        round_number=current_round,
        bracket_type=bracket_type
    ).all()
    
    # Check if all matches are complete
    if any(m.winner_id is None for m in current_matches):
        return False
    
    winners = [m.winner_id for m in current_matches]
    
    # If only one winner left in winners bracket and we're in grand finals
    if bracket_type == 'winners' and current_round >= math.ceil(math.log2(len(winners) * 2)):
        return True
    
    next_round = current_round + 1
    
    # Special case for losers bracket finals
    if bracket_type == 'losers' and len(winners) == 1:
        # Create grand finals match
        winners_final_winner = Match.query.filter_by(
            tournament_id=tournament_id,
            bracket_type='winners',
            round_number=current_round
        ).first().winner_id
        
        match = Match(
            tournament_id=tournament_id,
            round_number=next_round,
            bracket_type='grand_finals',
            team1_id=winners_final_winner,
            team2_id=winners[0],
            winner_id=None
        )
        db.session.add(match)
        db.session.commit()
        return True
    
    # Create next round matches
    for i in range(0, len(winners), 2):
        team1_id = winners[i]
        team2_id = winners[i+1] if i+1 < len(winners) else None
        
        match = Match(
            tournament_id=tournament_id,
            round_number=next_round,
            bracket_type=bracket_type,
            team1_id=team1_id,
            team2_id=team2_id,
            winner_id=None
        )
        db.session.add(match)
    
    # For winners bracket, also create losers bracket matches
    if bracket_type == 'winners':
        losers = []
        for m in current_matches:
            if m.team2_id:  # Only if it wasn't a bye
                losers.append(m.team1_id if m.winner_id == m.team2_id else m.team2_id)
        
        if losers:
            # Create losers bracket matches (only for first round)
            if current_round == 1:
                for i in range(0, len(losers), 2):
                    team1_id = losers[i]
                    team2_id = losers[i+1] if i+1 < len(losers) else None
                    
                    match = Match(
                        tournament_id=tournament_id,
                        round_number=1,
                        bracket_type='losers',
                        team1_id=team1_id,
                        team2_id=team2_id,
                        winner_id=None
                    )
                    db.session.add(match)
            else:
                # For subsequent rounds, losers drop down from winners bracket
                for loser_id in losers:
                    match = Match(
                        tournament_id=tournament_id,
                        round_number=current_round * 2 - 1,  # Special round numbering
                        bracket_type='losers',
                        team1_id=loser_id,
                        team2_id=None,  # Will be filled by previous losers bracket winner
                        winner_id=None
                    )
                    db.session.add(match)
    
    db.session.commit()
    return True

if __name__ == '__main__':
    app.run(debug=True)