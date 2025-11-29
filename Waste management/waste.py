#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import time, json, os, atexit, logging, tempfile
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-insecure-key-change-me')
app.config['PERMANENT_SESSION_LIFETIME'] = 300
app.config['APP_DATA_FILE'] = os.environ.get('APP_DATA_FILE', 'app_data.json')
app.config['ALLOW_PLAIN_REGISTER'] = os.environ.get('ALLOW_PLAIN_REGISTER', 'True').lower() in ('1', 'true', 'yes')
CORS(app, resources={r"/api/*": {"origins": "*"}})
logger = logging.getLogger("wastemanagement")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s'))
    logger.addHandler(h)
logger.setLevel(logging.INFO)
DATA_FILE = app.config['APP_DATA_FILE']
next_user_id = 101
users = {}
mock_bins = []
mock_history = []
class User(UserMixin):
    def __init__(self, id, username, password_hash, role, mobile=None, manager_id=None):
        self.id = str(id); self.username = username; self.password_hash = password_hash
        self.role = role; self.mobile = mobile; self.manager_id = manager_id
    def get_id(self): return self.id
def get_user_by_mobile(mobile):
    return next((u for u in users.values() if u.mobile == mobile), None)
def generate_mock_otp():
    return "1234"
def atomic_write_json(path, data):
    try:
        dirpath = os.path.dirname(os.path.abspath(path)) or "."
        with tempfile.NamedTemporaryFile('w', dir=dirpath, delete=False, encoding='utf-8') as tf:
            json.dump(data, tf, indent=4); tempname = tf.name
        os.replace(tempname, path)
        logger.debug("Atomic write to %s successful.", path)
        return True
    except Exception as e:
        logger.exception("Atomic write to %s failed: %s", path, e)
        try:
            if 'tempname' in locals() and os.path.exists(tempname): os.remove(tempname)
        except Exception:
            pass
        return False
def save_data():
    global next_user_id
    try:
        data = {'users': {username: {'id': user.id, 'password_hash': user.password_hash, 'role': user.role, 'mobile': user.mobile, 'manager_id': getattr(user, 'manager_id', None)} for username, user in users.items() if user.role != 'admin'}, 'mock_bins': mock_bins, 'mock_history': mock_history, 'next_user_id': next_user_id}
        ok = atomic_write_json(DATA_FILE, data)
        if ok: logger.info("Data saved to %s", DATA_FILE)
        else: logger.error("Failed to save data to %s", DATA_FILE)
    except Exception as e:
        logger.exception("Unexpected error saving data: %s", e)
def load_data():
    global users, mock_bins, mock_history, next_user_id
    system_user_entry = {'system_admin': User(id='000', username='system_admin', password_hash='', role='admin')}
    if not os.path.exists(DATA_FILE) or os.stat(DATA_FILE).st_size == 0:
        users.clear(); users.update(system_user_entry); mock_bins.clear(); mock_history.clear()
        mock_history.append({"event": "System Initialized (Clean Start)", "time": time.strftime("%Y-%m-%d %H:%M"), "actor": "System"})
        next_user_id = 101; logger.info("Initialized new data store (%s).", DATA_FILE); return
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        users_data = data.get('users', {})
        users.clear(); users.update(system_user_entry)
        for username, user_info in users_data.items():
            try:
                users[username] = User(id=user_info['id'], username=username, password_hash=user_info['password_hash'], role=user_info['role'], mobile=user_info.get('mobile'), manager_id=user_info.get('manager_id'))
            except Exception:
                logger.exception("Skipping malformed user entry for username=%s", username)
        mock_bins.clear(); mock_bins.extend(data.get('mock_bins', []))
        mock_history.clear(); mock_history.extend(data.get('mock_history', []))
        next_user_id = data.get('next_user_id', 101); logger.info("Data loaded from %s.", DATA_FILE)
    except Exception as e:
        logger.exception("Error loading data from %s: %s. Reinitializing store.", DATA_FILE, e)
        users.clear(); users.update(system_user_entry); mock_bins.clear(); mock_history.clear()
        mock_history.append({"event": "Load Error - System Reinitialized", "time": time.strftime("%Y-%m-%d %H:%M"), "actor": "System"}); next_user_id = 101
login_manager = LoginManager(); login_manager.init_app(app)
login_manager.login_view = 'login'; login_manager.login_message = "Please log in to access this page."
@login_manager.user_loader
def load_user(user_id):
    return next((u for u in users.values() if u.id == user_id), None)
def manager_required(func):
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'manager':
            logger.warning("Unauthorized manager access attempt by user: %s", getattr(current_user, 'username', None))
            flash('Access denied. Manager role required.', 'error')
            if request.path.startswith('/api/'): return jsonify({"message": "Manager role required."}), 403
            return func(*args, **kwargs)
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__; return wrapper
@app.after_request
def after_request(response):
    try:
        if request.method in ['POST', 'DELETE', 'PUT'] and request.path.startswith('/api/'):
            if response.status_code in [200, 201, 204]: save_data()
    except Exception:
        logger.exception("Error in after_request persistence hook.")
    return response
#  [All routes from /login to /api/public/managers-debug remain the same] 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password'); user = users.get(username)
        if user and user.role != 'admin' and check_password_hash(user.password_hash, password):
            login_user(user); flash(f'Logged in as {user.username} ({user.role}).', 'success'); logger.info("User logged in: %s (%s)", user.username, user.role); return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error'); logger.info("Failed login attempt for username: %s", username)
    return render_template('login.html')
@app.route('/request_otp', methods=['POST'])
def request_otp():
    mobile = request.form.get('mobile'); action = request.form.get('action')
    if not mobile or len(mobile) < 10: return jsonify({"success": False, "message": "Invalid mobile number."})
    user_exists = get_user_by_mobile(mobile)
    if action == 'reset' and not user_exists: return jsonify({"success": False, "message": "No account found with this number to reset."})
    if action == 'register' and user_exists: return jsonify({"success": False, "message": "An account with this mobile number already exists."})
    session['otp_mobile'] = mobile; session['otp_code'] = generate_mock_otp(); session['otp_action'] = action; session.permanent = True
    logger.info("OTP requested for mobile=%s action=%s", mobile, action)
    return jsonify({"success": True, "message": f"OTP sent to {mobile}. (Mock code: {session['otp_code']})"})
@app.route('/register', methods=['GET', 'POST'])
def register():
    global next_user_id
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        if request.form.get('step') == 'verify':
            input_otp = request.form.get('otp'); mobile = request.form.get('mobile_hidden')
            session_otp = session.pop('otp_code', None); session_mobile = session.pop('otp_mobile', None)
            if not mobile or mobile != session_mobile or session_otp != input_otp or not session_otp:
                flash('Invalid or expired OTP. Please restart registration.', 'error'); return redirect(url_for('register'))
            username = request.form.get('username_hidden'); password = request.form.get('password_hidden'); role = request.form.get('role_hidden'); manager_id = request.form.get('manager_id_hidden')
            if not username or not password or not role: flash('Missing registration fields.', 'error'); return redirect(url_for('register'))
            if username in users: flash('Username already exists. Choose a different one.', 'error'); return redirect(url_for('register'))
            if role == 'worker':
                if not manager_id: flash('Worker registration requires association with a Manager.', 'error'); return redirect(url_for('register'))
                manager_user = next((u for u in users.values() if u.id == str(manager_id) and u.role == 'manager'), None)
                if not manager_user: flash('Invalid Manager ID specified.', 'error'); return redirect(url_for('register'))
                manager_id = str(manager_id)
            else: manager_id = None
            new_id = next_user_id; next_user_id += 1
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(new_id, username, password_hash, role, mobile, manager_id); users[username] = new_user; save_data()
            logger.info("New user registered (OTP flow): %s (%s)", username, role)
            flash(f'Registration successful! You can now log in as {username} ({role}).', 'success'); return redirect(url_for('login'))
        if app.config.get('ALLOW_PLAIN_REGISTER', True):
            username = request.form.get('username') or request.form.get('username_hidden'); password = request.form.get('password') or request.form.get('password_hidden'); mobile = request.form.get('mobile') or request.form.get('mobile_hidden'); role = request.form.get('role') or request.form.get('role_hidden'); manager_id = request.form.get('associateManager') or request.form.get('manager_id_hidden')
            if not username or not password or not role: flash('Please provide username, password and role.', 'error'); return redirect(url_for('register'))
            if username in users: flash('Username already exists. Choose a different one.', 'error'); return redirect(url_for('register'))
            if role == 'worker':
                if not manager_id: flash('Worker registration requires association with a Manager.', 'error'); return redirect(url_for('register'))
                manager_user = next((u for u in users.values() if u.id == str(manager_id) and u.role == 'manager'), None)
                if not manager_user: flash('Invalid Manager ID specified.', 'error'); return redirect(url_for('register'))
                manager_id = str(manager_id)
            else: manager_id = None
            new_id = next_user_id; next_user_id += 1
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(new_id, username, password_hash, role, mobile, manager_id); users[username] = new_user; save_data()
            logger.info("New user registered (direct fallback): %s (%s)", username, role)
            flash(f'Registration successful! You can now log in as {username} ({role}).', 'success'); return redirect(url_for('login'))
        flash('Registration not allowed (missing OTP).', 'error'); return redirect(url_for('register'))
    return render_template('register.html')
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        form_mobile = request.form.get('mobile_hidden'); input_otp = request.form.get('otp'); new_password = request.form.get('new_password')
        session_otp = session.pop('otp_code', None); session_mobile = session.pop('otp_mobile', None); user_to_reset = get_user_by_mobile(form_mobile)
        if not user_to_reset or form_mobile != session_mobile or session_otp != input_otp or not session_otp:
            flash('Invalid OTP or session expired. Please restart the process.', 'error'); return redirect(url_for('forgot_password'))
        user_to_reset.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256'); save_data()
        logger.info("Password reset for mobile=%s user=%s", form_mobile, user_to_reset.username); flash('Password successfully reset. You can now log in.', 'success'); return redirect(url_for('login'))
    return render_template('forgot_password.html')
@app.route('/logout')
@login_required
def logout():
    logger.info("User logged out: %s", current_user.username); logout_user(); flash('You have been logged out.', 'success'); return redirect(url_for('login'))
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('dashboard.html', user_role=current_user.role, current_username=current_user.username, current_user_id=current_user.id)
    return render_template('index.html')
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "time": time.strftime("%Y-%m-%d %H:%M:%S")})
@app.route('/api/managers', methods=['GET'])
@login_required
def get_managers():
    manager_list = [{"id": u.id, "username": u.username, "role": u.role} for u in users.values() if u.role == 'manager']
    worker_list = [{"id": u.id, "username": u.username, "role": u.role, "manager_id": u.manager_id} for u in users.values() if u.role == 'worker']
    return jsonify({'managers': manager_list, 'workers': worker_list})
@app.route('/api/public/managers', methods=['GET'])
def public_get_managers_public():
    try:
        manager_list = []
        for u in users.values():
            try:
                if u.role == 'manager': 
                    manager_list.append({"id": u.id, "username": u.username, "role": u.role})
            except Exception:
                try:
                    if u.get('role') == 'manager':
                         manager_list.append({"id": u.get('id'), "username": u.get('username'), "role": u.get('role')})
                except Exception:
                    pass
        logger.info("Public managers requested; returning %d managers", len(manager_list))
        return jsonify({'managers': manager_list})
    except Exception as e:
        logger.exception("public_get_managers failed: %s", e)
        return jsonify({'managers': [], 'error': 'failed to list managers'}), 500
@app.route('/api/public/managers-debug', methods=['GET'])
def public_get_managers_debug():
    sample = {'managers': [{'id': '201', 'username': 'demo_manager', 'role': 'manager'}]}; logger.info("Public managers debug requested"); return jsonify(sample)

#--- FILTERED HISTORY ENDPOINT
@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    if current_user.role == 'manager':
        my_workers = [
            u.username for u in users.values() 
            if getattr(u, 'manager_id', None) == current_user.id
        ]
        relevant_actors = set([current_user.username] + my_workers)
        filtered = [h for h in mock_history if h.get('actor') in relevant_actors]
    elif current_user.role == 'worker':
        filtered = [h for h in mock_history if h.get('actor') == current_user.username]
    else:
        filtered = mock_history
    return jsonify(list(reversed(filtered)))

@app.route('/api/bins', methods=['GET'])
@login_required
def get_bins():
    if current_user.role == 'worker':
        worker_id = int(current_user.id)
        worker_bins = [bin for bin in mock_bins if (bin.get('assigned_worker_id') == worker_id and bin['status'] == 'scheduled') or (bin['status'] == 'full')]
        return jsonify(worker_bins)
    
    if current_user.role == 'manager':
        manager_id = current_user.id
        manager_bins = [bin for bin in mock_bins if str(bin.get('manager_id')) == manager_id]
        return jsonify(manager_bins)
            
    return jsonify(mock_bins)

@app.route('/api/bins', methods=['POST'])
@manager_required
def add_bin():
    global mock_bins
    try:
        data = request.json

        # global unique id (keeps existing behavior and references stable)
        global_new_id = max((b.get('id', 0) for b in mock_bins), default=0) + 1

        # manager owner id (string)
        manager_id = current_user.id

        # compute local per-manager id (starts at 1 for each manager)
        existing_local_ids = [b.get('local_id', 0) for b in mock_bins if str(b.get('manager_id')) == manager_id]
        local_new_id = max(existing_local_ids, default=0) + 1

        new_bin = {
            "id": global_new_id,
            "local_id": local_new_id,               # new field: per-manager incremental id starting at 1
            "type": data.get("type", "unknown"),
            "status": data.get("status", "empty"),
            "location": data.get("location", "Unknown Location"),
            "last_pickup": None,
            "assigned_worker_id": None,
            "manager_id": manager_id
        }

        mock_bins.append(new_bin)
        # keep a predictable ordering; sort by global id to preserve earlier behavior
        mock_bins.sort(key=lambda b: b.get('id', 0))

        logger.info("Manager %s added bin: %s", current_user.username, new_bin)
        return jsonify(new_bin), 201
    except Exception as e:
        logger.exception("Error adding bin: %s", e)
        return jsonify({"message": "Error adding bin"}), 500

@app.route('/api/bins/<int:bin_id>', methods=['DELETE'])
@manager_required
def delete_bin(bin_id):
    global mock_bins
    
    bin_to_delete = next((b for b in mock_bins if b['id'] == bin_id), None)

    if not bin_to_delete:
        logger.warning("Attempted to delete missing bin id=%s", bin_id); 
        return jsonify({"message": "Bin not found."}), 404
    
    if str(bin_to_delete.get('manager_id')) != current_user.id:
        logger.warning("Manager %s attempted to delete unowned bin id=%s", current_user.username, bin_id); 
        return jsonify({"message": "Access denied. You do not own this bin."}), 403

    mock_bins[:] = [bin for bin in mock_bins if bin['id'] != bin_id]
    logger.info("Manager %s deleted owned bin id=%s", current_user.username, bin_id); 
    return jsonify({"message": f"Bin {bin_id} deleted."}), 200

@app.route('/api/bins/bulk', methods=['POST'])
@manager_required
def bulk_update():
    data = request.json; ids = data.get('ids', []); new_status = data.get('status')
    if not ids or not new_status: return jsonify({"message": "Missing IDs or status."}), 400
    
    count = 0
    manager_id = current_user.id 
    
    for bin in mock_bins:
        if bin['id'] in ids and str(bin.get('manager_id')) == manager_id: 
            bin['status'] = new_status
            count += 1

    logger.info("Manager %s applied bulk update to %d owned bins, status=%s", current_user.username, count, new_status); 
    return jsonify({"updated": count, "status": new_status})

@app.route('/api/pickups/schedule', methods=['POST'])
@manager_required
def schedule_pickup():
    global mock_history
    data = request.json; worker_id_to_assign = str(data.get('worker_id'))
    
    worker_user = next((u for u in users.values() if u.id == worker_id_to_assign and u.role == 'worker'), None)
    if not worker_user: 
        return jsonify({"message": "Invalid or missing worker ID or user is not a worker."}), 400
    
    if str(worker_user.manager_id) != current_user.id:
        return jsonify({"message": f"Authorization Failed. Worker ID {worker_id_to_assign} is not associated with Manager ID {current_user.id}."}), 403

    now = time.strftime("%Y-%m-%d %H:%M"); scheduled_count = 0
    manager_id = current_user.id 

    for bin in mock_bins:
        if bin['status'] == 'full' and str(bin.get('manager_id')) == manager_id: 
            bin['status'] = 'scheduled'
            bin['assigned_worker_id'] = int(worker_id_to_assign)
            scheduled_count += 1
            
    if scheduled_count > 0:
        mock_history.append({"event": f"Scheduled {scheduled_count} pickups, assigned to {worker_user.username} (ID {worker_user.id})", "time": now, "actor": current_user.username})
        logger.info("Manager %s scheduled %d full bins (owned by them) to worker %s", current_user.username, scheduled_count, worker_user.username)
        
    return jsonify({"scheduled": scheduled_count, "time": now, "worker_id": worker_id_to_assign})

@app.route('/api/bins/status/<int:bin_id>', methods=['POST'])
@login_required
def update_bin_status_by_id(bin_id):
    data = request.json
    new_status = data.get('status')
    image_data = data.get('image_data') 
    
    bin_obj = next((b for b in mock_bins if b['id'] == bin_id), None)
    if not bin_obj: 
        logger.warning("Bin not found for status update id=%s", bin_id)
        return jsonify({"message": "Bin not found."}), 404
    
    manager_id = bin_obj.get('manager_id') 
    
    if current_user.role == 'manager':
        if str(manager_id) != current_user.id:
            logger.warning("Manager %s attempted to update unowned bin id=%s", current_user.username, bin_id)
            return jsonify({"message": "Access denied. You do not own this bin."}), 403
        
        bin_obj['status'] = new_status
        if new_status == 'empty':
            bin_obj['last_pickup'] = time.strftime("%Y-%m-%d %H:%M")
            bin_obj['assigned_worker_id'] = None
        logger.info("Manager %s set owned bin %s status=%s", current_user.username, bin_id, new_status)
        return jsonify({"message": f"Manager updated bin {bin_id} status to {new_status}"})
    
    elif current_user.role == 'worker':
        worker_id = int(current_user.id)
        is_assigned = bin_obj.get('assigned_worker_id') == worker_id
        
        if new_status == 'empty':
            if bin_obj['status'] == 'scheduled' and is_assigned:
                if not image_data:
                    return jsonify({"message": "Photo confirmation is required to mark pickup as complete."}), 400
                
                pickup_time = time.strftime("%Y-%m-%d %H:%M")
                bin_obj['status'] = 'empty'
                bin_obj['last_pickup'] = pickup_time
                bin_obj['assigned_worker_id'] = None
                event_message = f"Pickup completed for Bin ID {bin_id}. Photo proof submitted."
                mock_history.append({
                    "event": event_message, 
                    "time": pickup_time, 
                    "actor": current_user.username, 
                    "image_data": image_data
                })
                logger.info("Worker %s completed pickup for bin %s with photo proof.", current_user.username, bin_id)
                return jsonify({
                    "message": f"Worker confirmed pickup and set bin {bin_id} to empty.", 
                    "pickup_done": True, 
                    "bin_id": bin_id, 
                    "time": pickup_time, 
                    "image_data_submitted": True
                })
            else:
                return jsonify({"message": "Worker can only mark their assigned scheduled bins as empty."}), 403

        elif new_status == 'full':
            if bin_obj['status'] != 'full' and not bin_obj['assigned_worker_id']:
                bin_obj['status'] = 'full'
                logger.info("Worker %s reported bin %s as full", current_user.username, bin_id)
                return jsonify({"message": f"Worker reported bin {bin_id} status to {new_status}."})
            else:
                return jsonify({"message": "Cannot set status to full on assigned or already full bin."}), 403
        else:
            return jsonify({"message": "Unauthorized status change for worker (only 'full' or 'empty' allowed)."}), 403
    
    logger.warning("Unauthorized status change attempt by user=%s", getattr(current_user, 'username', None)); return jsonify({"message": "Unauthorized action."}), 403

@app.route('/api/pickups/done', methods=['POST'])
@manager_required
def pickup_done_all_scheduled():
    now = time.strftime("%Y-%m-%d %H:%M"); updated_count = 0
    manager_id = current_user.id
    
    for bin in mock_bins:
        if bin['status'] == 'scheduled' and str(bin.get('manager_id')) == manager_id:
            bin['status'] = 'empty'; bin['last_pickup'] = now; bin['assigned_worker_id'] = None; updated_count += 1
            
    if updated_count > 0:
        mock_history.append({"event": f"Manager confirmed pickup of {updated_count} scheduled bins (bulk action)", "time": now, "actor": current_user.username})
        logger.info("Manager %s marked %d scheduled bins (owned by them) as done", current_user.username, updated_count)
    return jsonify({"updated": updated_count, "time": now})

if __name__ == '__main__':
    load_data(); atexit.register(save_data)
    port = int(os.environ.get('PORT', 10000))
    logger.info("Starting Flask server on port %s (ALLOW_PLAIN_REGISTER=%s)", port, app.config.get('ALLOW_PLAIN_REGISTER'))
    app.run(host='0.0.0.0', port=port)