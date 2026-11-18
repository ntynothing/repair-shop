import os, re, sqlite3, uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
STATUSES = ['Принята', 'В диагностике', 'В ремонте', 'Готова к выдаче', 'Выдана']
DEVICES = ['Смартфон', 'Ноутбук', 'Планшет', 'Компьютер', 'Телевизор', 'Другое']
FAULTS = ['Не включается', 'Разбит экран или корпус', 'Не заряжается', 'Перегрев или шум', 'Программная ошибка', 'Другое']
ROLES = {'client': 'Клиент', 'master': 'Мастер', 'admin': 'Администратор'}
EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
TOTAL = "(r.work_cost + COALESCE((SELECT SUM(rp.qty*p.price) FROM request_parts rp JOIN parts p ON p.id=rp.part_id WHERE rp.request_id=r.id),0))"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-me')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['DB'] = os.path.join(BASE, 'repair.db')
app.config['UPLOADS'] = os.path.join(BASE, 'static', 'uploads')


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DB'])
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    d = g.pop('db', None)
    if d:
        d.close()


def q(sql, a=(), one=False):
    r = db().execute(sql, a).fetchall()
    if one:
        return r[0] if r else None
    return r


def ex(sql, a=()):
    c = db().execute(sql, a)
    db().commit()
    return c.lastrowid


def num(v, lo=0, hi=1000000):
    try:
        x = float(str(v).replace(',', '.'))
    except ValueError:
        return None
    return x if lo <= x <= hi else None


def intval(v, lo=0, hi=100000):
    try:
        x = int(str(v).strip())
    except ValueError:
        return None
    return x if lo <= x <= hi else None


def home_for(u):
    return url_for({'client': 'cabinet', 'master': 'master', 'admin': 'admin'}[u['role']])


@app.before_request
def load_user():
    g.user = None
    if session.get('uid'):
        g.user = q('SELECT * FROM users WHERE id=? AND active=1', (session['uid'],), True)


@app.context_processor
def inject():
    return dict(user=g.get('user'), statuses=STATUSES, roles=ROLES)


def need(*allowed):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not g.user:
                return redirect(url_for('login', next=request.path))
            if allowed and g.user['role'] not in allowed:
                abort(403)
            return f(*a, **k)
        return w
    return deco


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def errors(e):
    msg = {403: 'Доступ запрещён', 404: 'Страница не найдена', 413: 'Файл слишком большой (максимум 5 МБ)'}[e.code]
    return render_template('error.html', code=e.code, msg=msg), e.code


def save_photo(f):
    if not f or not f.filename:
        return None, None
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ('jpg', 'jpeg', 'png', 'webp'):
        return None, 'Фото: допустимы только jpg, png, webp'
    os.makedirs(app.config['UPLOADS'], exist_ok=True)
    name = uuid.uuid4().hex + '.' + ext
    f.save(os.path.join(app.config['UPLOADS'], name))
    return name, None


@app.route('/')
def catalog():
    return render_template('index.html', services=q('SELECT * FROM services ORDER BY name'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    f = request.form
    if request.method == 'POST':
        name = f.get('name', '').strip()
        email = f.get('email', '').strip().lower()
        phone = f.get('phone', '').strip()
        p1, p2 = f.get('password', ''), f.get('password2', '')
        err = []
        if not 2 <= len(name) <= 60:
            err.append('Имя: от 2 до 60 символов')
        if not EMAIL.match(email) or len(email) > 100:
            err.append('Некорректный e-mail')
        if not 10 <= len(re.sub(r'\D', '', phone)) <= 15:
            err.append('Телефон: от 10 до 15 цифр')
        if not 6 <= len(p1) <= 64:
            err.append('Пароль: от 6 до 64 символов')
        if p1 != p2:
            err.append('Пароли не совпадают')
        if not err and q('SELECT 1 FROM users WHERE email=?', (email,), True):
            err.append('Этот e-mail уже зарегистрирован')
        if err:
            for e in err:
                flash(e, 'err')
            return render_template('register.html', f=f)
        ex('INSERT INTO users(name,email,phone,password_hash,role,created_at) VALUES(?,?,?,?,?,?)',
           (name, email, phone, generate_password_hash(p1), 'client', now()))
        flash('Регистрация прошла успешно. Войдите в аккаунт.', 'ok')
        return redirect(url_for('login'))
    return render_template('register.html', f={})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        u = q('SELECT * FROM users WHERE email=?', (email,), True)
        if u and u['active'] and check_password_hash(u['password_hash'], request.form.get('password', '')):
            session.clear()
            session['uid'] = u['id']
            nxt = request.args.get('next', '')
            if nxt.startswith('/') and not nxt.startswith('//'):
                return redirect(nxt)
            return redirect(home_for(u))
        flash('Неверный e-mail или пароль', 'err')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('catalog'))


@app.route('/request/new', methods=['GET', 'POST'])
@need('client')
def req_new():
    f = request.form
    if request.method == 'POST':
        dev, fault = f.get('device', ''), f.get('fault', '')
        model, problem = f.get('model', '').strip(), f.get('problem', '').strip()
        err = []
        if dev not in DEVICES:
            err.append('Выберите тип устройства')
        if fault not in FAULTS:
            err.append('Выберите вид неисправности')
        if not 2 <= len(model) <= 80:
            err.append('Модель: от 2 до 80 символов')
        if not 10 <= len(problem) <= 1000:
            err.append('Описание неисправности: от 10 до 1000 символов')
        photo = None
        if not err:
            photo, e = save_photo(request.files.get('photo'))
            if e:
                err.append(e)
        if err:
            for e in err:
                flash(e, 'err')
            return render_template('new_request.html', f=f, devices=DEVICES, faults=FAULTS)
        rid = ex('INSERT INTO requests(client_id,device_type,model,fault,problem,photo,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                 (g.user['id'], dev, model, fault, problem, photo, now(), now()))
        flash('Заявка №%d создана' % rid, 'ok')
        return redirect(url_for('req_view', rid=rid))
    return render_template('new_request.html', f={}, devices=DEVICES, faults=FAULTS)


@app.route('/cabinet')
@need('client')
def cabinet():
    rows = q('SELECT r.*, ' + TOTAL + ' AS total FROM requests r WHERE client_id=? ORDER BY id DESC', (g.user['id'],))
    return render_template('cabinet.html', rows=rows)


def get_request(rid):
    r = q('SELECT r.*, ' + TOTAL + ' AS total, c.name cname, c.phone cphone, m.name mname FROM requests r '
          'JOIN users c ON c.id=r.client_id LEFT JOIN users m ON m.id=r.master_id WHERE r.id=?', (rid,), True)
    if not r:
        abort(404)
    u = g.user
    if (u['role'] == 'client' and r['client_id'] != u['id']) or (u['role'] == 'master' and r['master_id'] != u['id']):
        abort(403)
    return r


@app.route('/request/<int:rid>', methods=['GET', 'POST'])
@need()
def req_view(rid):
    r = get_request(rid)
    u = g.user
    staff = u['role'] in ('master', 'admin')
    if request.method == 'POST':
        f = request.form
        act = f.get('action')
        if act == 'comment':
            text = f.get('text', '').strip()
            if 1 <= len(text) <= 500:
                ex('INSERT INTO comments(request_id,user_id,text,created_at) VALUES(?,?,?,?)', (rid, u['id'], text, now()))
            else:
                flash('Комментарий: от 1 до 500 символов', 'err')
        elif staff and act == 'status':
            if f.get('status') in STATUSES:
                ex('UPDATE requests SET status=?, updated_at=? WHERE id=?', (f['status'], now(), rid))
                flash('Статус обновлён', 'ok')
            else:
                flash('Недопустимый статус', 'err')
        elif staff and act == 'cost':
            c = num(f.get('work_cost'))
            if c is None:
                flash('Стоимость работ: число от 0 до 1 000 000', 'err')
            else:
                ex('UPDATE requests SET work_cost=?, updated_at=? WHERE id=?', (c, now(), rid))
                flash('Стоимость работ сохранена', 'ok')
        elif staff and act == 'part':
            p = q('SELECT * FROM parts WHERE id=?', (intval(f.get('part_id'), 1),), True)
            qty = intval(f.get('qty'), 1, 1000)
            if not p or not qty:
                flash('Выберите запчасть и количество от 1 до 1000', 'err')
            elif qty > p['quantity']:
                flash('На складе только %d шт.' % p['quantity'], 'err')
            else:
                ex('UPDATE parts SET quantity=quantity-? WHERE id=?', (qty, p['id']))
                ex('INSERT INTO request_parts(request_id,part_id,qty) VALUES(?,?,?)', (rid, p['id'], qty))
                ex('UPDATE requests SET updated_at=? WHERE id=?', (now(), rid))
                flash('Запчасть добавлена', 'ok')
        return redirect(url_for('req_view', rid=rid))
    comments = q('SELECT c.*, u.name, u.role FROM comments c JOIN users u ON u.id=c.user_id WHERE request_id=? ORDER BY c.id', (rid,))
    used = q('SELECT p.name, p.sku, p.price, rp.qty FROM request_parts rp JOIN parts p ON p.id=rp.part_id WHERE rp.request_id=?', (rid,))
    parts = q('SELECT * FROM parts WHERE quantity>0 ORDER BY name') if staff else []
    return render_template('req.html', r=r, comments=comments, used=used, parts=parts, staff=staff)


@app.route('/request/<int:rid>/receipt')
@need()
def receipt(rid):
    r = get_request(rid)
    used = q('SELECT p.name, p.price, rp.qty FROM request_parts rp JOIN parts p ON p.id=rp.part_id WHERE rp.request_id=?', (rid,))
    return render_template('receipt.html', r=r, used=used)


@app.route('/track', methods=['GET', 'POST'])
def track():
    r = None
    if request.method == 'POST':
        rid = intval(request.form.get('id'), 1, 10 ** 9)
        digits = re.sub(r'\D', '', request.form.get('phone', ''))
        if rid and len(digits) >= 4:
            row = q('SELECT r.id, r.status, r.device_type, r.model, r.updated_at, c.phone FROM requests r JOIN users c ON c.id=r.client_id WHERE r.id=?', (rid,), True)
            if row and re.sub(r'\D', '', row['phone']).endswith(digits[-4:]):
                r = row
        if not r:
            flash('Заявка не найдена. Проверьте номер и последние 4 цифры телефона', 'err')
    return render_template('track.html', r=r)


@app.route('/master')
@need('master')
def master():
    st = request.args.get('status', '')
    sql = 'SELECT r.*, ' + TOTAL + ' AS total FROM requests r WHERE master_id=?'
    a = [g.user['id']]
    if st in STATUSES:
        sql += ' AND status=?'
        a.append(st)
    return render_template('master.html', rows=q(sql + ' ORDER BY id DESC', a), cur=st)


@app.route('/api/status', methods=['POST'])
@need('admin', 'master')
def api_status():
    d = request.get_json(silent=True) or {}
    r = q('SELECT * FROM requests WHERE id=?', (d.get('id'),), True)
    if d.get('status') not in STATUSES:
        return jsonify(ok=False), 400
    if not r or (g.user['role'] == 'master' and r['master_id'] != g.user['id']):
        return jsonify(ok=False), 403
    ex('UPDATE requests SET status=?, updated_at=? WHERE id=?', (d['status'], now(), r['id']))
    return jsonify(ok=True)


@app.route('/admin')
@need('admin')
def admin():
    rows = q('SELECT r.*, c.name cname, m.name mname FROM requests r JOIN users c ON c.id=r.client_id LEFT JOIN users m ON m.id=r.master_id ORDER BY r.id DESC')
    masters = q("SELECT id,name FROM users WHERE role='master' AND active=1 ORDER BY name")
    return render_template('admin.html', rows=rows, masters=masters)


@app.route('/admin/assign', methods=['POST'])
@need('admin')
def assign():
    rid = intval(request.form.get('id'), 1, 10 ** 9)
    mid = intval(request.form.get('master_id'), 1, 10 ** 9)
    if not rid or not q('SELECT 1 FROM requests WHERE id=?', (rid,), True):
        abort(404)
    if mid and not q("SELECT 1 FROM users WHERE id=? AND role='master' AND active=1", (mid,), True):
        abort(400)
    ex('UPDATE requests SET master_id=?, updated_at=? WHERE id=?', (mid, now(), rid))
    flash('Мастер назначен' if mid else 'Назначение снято', 'ok')
    return redirect(url_for('admin'))


@app.route('/admin/services', methods=['GET', 'POST'])
@need('admin')
def a_services():
    if request.method == 'POST':
        f = request.form
        act = f.get('action')
        if act == 'delete':
            ex('DELETE FROM services WHERE id=?', (intval(f.get('id'), 1),))
            flash('Услуга удалена', 'ok')
        elif act in ('add', 'update'):
            name, desc = f.get('name', '').strip(), f.get('description', '').strip()
            pf, pt = num(f.get('price_from')), num(f.get('price_to'))
            if not 2 <= len(name) <= 80 or len(desc) > 300 or pf is None or pt is None or pt < pf:
                flash('Проверьте поля: название 2–80 символов, цена «до» не меньше цены «от»', 'err')
            elif act == 'add':
                ex('INSERT INTO services(name,description,price_from,price_to) VALUES(?,?,?,?)', (name, desc, pf, pt))
                flash('Услуга добавлена', 'ok')
            else:
                ex('UPDATE services SET name=?, description=?, price_from=?, price_to=? WHERE id=?', (name, desc, pf, pt, intval(f.get('id'), 1)))
                flash('Услуга сохранена', 'ok')
        return redirect(url_for('a_services'))
    return render_template('admin_services.html', rows=q('SELECT * FROM services ORDER BY name'))


@app.route('/admin/users', methods=['GET', 'POST'])
@need('admin')
def a_users():
    if request.method == 'POST':
        f = request.form
        act = f.get('action')
        if act == 'add':
            name, email, phone = f.get('name', '').strip(), f.get('email', '').strip().lower(), f.get('phone', '').strip()
            pw, role = f.get('password', ''), f.get('role')
            if not (2 <= len(name) <= 60 and EMAIL.match(email) and 10 <= len(re.sub(r'\D', '', phone)) <= 15 and 6 <= len(pw) <= 64 and role in ROLES):
                flash('Проверьте поля формы', 'err')
            elif q('SELECT 1 FROM users WHERE email=?', (email,), True):
                flash('Этот e-mail уже используется', 'err')
            else:
                ex('INSERT INTO users(name,email,phone,password_hash,role,created_at) VALUES(?,?,?,?,?,?)', (name, email, phone, generate_password_hash(pw), role, now()))
                flash('Пользователь добавлен', 'ok')
        elif act == 'update':
            uid = intval(f.get('id'), 1)
            if uid == g.user['id']:
                flash('Нельзя изменить собственную учётную запись', 'err')
            elif f.get('role') in ROLES:
                ex('UPDATE users SET role=?, active=? WHERE id=?', (f['role'], 1 if f.get('active') == '1' else 0, uid))
                flash('Сохранено', 'ok')
        return redirect(url_for('a_users'))
    return render_template('admin_users.html', rows=q('SELECT * FROM users ORDER BY role, name'))


@app.route('/admin/parts', methods=['GET', 'POST'])
@need('admin')
def a_parts():
    if request.method == 'POST':
        f = request.form
        act = f.get('action')
        qty, price = intval(f.get('quantity'), 0, 100000), num(f.get('price'))
        if act == 'add':
            name, sku = f.get('name', '').strip(), f.get('sku', '').strip()
            mn = intval(f.get('min_qty'), 0, 100000)
            if not (2 <= len(name) <= 80 and 1 <= len(sku) <= 30) or qty is None or price is None or mn is None:
                flash('Проверьте поля формы', 'err')
            elif q('SELECT 1 FROM parts WHERE sku=?', (sku,), True):
                flash('Артикул уже существует', 'err')
            else:
                ex('INSERT INTO parts(name,sku,quantity,min_qty,price) VALUES(?,?,?,?,?)', (name, sku, qty, mn, price))
                flash('Запчасть добавлена', 'ok')
        elif act == 'update':
            if qty is None or price is None:
                flash('Количество и цена: неотрицательные числа', 'err')
            else:
                ex('UPDATE parts SET quantity=?, price=? WHERE id=?', (qty, price, intval(f.get('id'), 1)))
                flash('Сохранено', 'ok')
        elif act == 'delete':
            try:
                ex('DELETE FROM parts WHERE id=?', (intval(f.get('id'), 1),))
                flash('Запчасть удалена', 'ok')
            except sqlite3.IntegrityError:
                flash('Запчасть использована в заявках, удалить нельзя', 'err')
        return redirect(url_for('a_parts'))
    return render_template('parts.html', rows=q('SELECT * FROM parts ORDER BY name'))


@app.route('/admin/stats')
@need('admin')
def stats():
    by_month = q("SELECT strftime('%Y-%m',created_at) k, COUNT(*) v FROM requests GROUP BY k ORDER BY k")
    income = q("SELECT strftime('%Y-%m',r.created_at) k, ROUND(SUM(" + TOTAL + "),0) v FROM requests r WHERE status='Выдана' GROUP BY k ORDER BY k")
    faults = q('SELECT fault k, COUNT(*) v FROM requests GROUP BY fault ORDER BY v DESC')
    devices = q('SELECT device_type k, COUNT(*) v FROM requests GROUP BY device_type ORDER BY v DESC')
    load = q("SELECT u.name k, COUNT(r.id) v FROM users u LEFT JOIN requests r ON r.master_id=u.id AND r.status!='Выдана' WHERE u.role='master' GROUP BY u.id ORDER BY v DESC")
    total = q('SELECT COUNT(*) n FROM requests', one=True)['n']
    return render_template('stats.html', by_month=by_month, income=income, faults=faults, devices=devices, load=load, total=total)


def seed(c):
    ph = lambda p: generate_password_hash(p)
    t = now()
    c.executemany('INSERT INTO users(name,email,phone,password_hash,role,created_at) VALUES(?,?,?,?,?,?)', [
        ('Администратор', 'admin@shop.ru', '+79000000001', ph('admin123'), 'admin', t),
        ('Иван Мастеров', 'master@shop.ru', '+79000000002', ph('master123'), 'master', t),
        ('Пётр Электронов', 'master2@shop.ru', '+79000000003', ph('master123'), 'master', t),
        ('Анна Клиентова', 'client@shop.ru', '+79001234567', ph('client123'), 'client', t)])
    c.executemany('INSERT INTO services(name,description,price_from,price_to) VALUES(?,?,?,?)', [
        ('Диагностика', 'Проверка устройства и определение неисправности', 0, 500),
        ('Замена экрана смартфона', 'Замена дисплейного модуля', 2500, 9000),
        ('Замена аккумулятора', 'Новый аккумулятор с гарантией', 1200, 3500),
        ('Чистка ноутбука от пыли', 'Чистка системы охлаждения, замена термопасты', 1500, 2500),
        ('Установка Windows', 'Установка системы и драйверов', 1000, 2000),
        ('Ремонт разъёма зарядки', 'Замена или пайка разъёма', 1500, 3000)])
    c.executemany('INSERT INTO parts(name,sku,quantity,min_qty,price) VALUES(?,?,?,?,?)', [
        ('Дисплейный модуль смартфона', 'DSP-001', 8, 3, 4200), ('Аккумулятор смартфона', 'BAT-010', 15, 5, 1100),
        ('Разъём зарядки Type-C', 'CON-020', 2, 4, 250), ('Термопаста', 'PST-030', 20, 5, 150),
        ('SSD 256 ГБ', 'SSD-256', 6, 2, 2800), ('Клавиатура ноутбука', 'KBD-040', 3, 2, 1900)])
    base = datetime.now()
    demo = [(60, 'Смартфон', 'Samsung A52', 'Разбит экран или корпус', 'Выдана', 800, 2, 1, 1), (45, 'Ноутбук', 'Lenovo IdeaPad', 'Перегрев или шум', 'Выдана', 1500, 3, 4, 1),
            (35, 'Смартфон', 'iPhone 11', 'Не заряжается', 'Выдана', 900, 2, 3, 1), (20, 'Планшет', 'Huawei MatePad', 'Не включается', 'Выдана', 1200, 3, None, 0),
            (12, 'Ноутбук', 'ASUS X515', 'Программная ошибка', 'Готова к выдаче', 1000, 2, None, 0), (6, 'Смартфон', 'Xiaomi Redmi 9', 'Не заряжается', 'В ремонте', 0, 3, None, 0),
            (3, 'Телевизор', 'LG 43', 'Не включается', 'В диагностике', 0, 2, None, 0), (1, 'Смартфон', 'Honor 10', 'Разбит экран или корпус', 'Принята', 0, None, None, 0)]
    for i, (d, dev, model, fault, st, cost, m, part, qty) in enumerate(demo, 1):
        dt = (base - timedelta(days=d)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute('INSERT INTO requests(client_id,master_id,device_type,model,fault,problem,status,work_cost,created_at,updated_at) VALUES(4,?,?,?,?,?,?,?,?,?)',
                  (m, dev, model, fault, 'Устройство требует ремонта, подробности при приёме', st, cost, dt, dt))
        if part:
            c.execute('INSERT INTO request_parts(request_id,part_id,qty) VALUES(?,?,1)', (i, part))
    c.execute("INSERT INTO comments(request_id,user_id,text,created_at) VALUES(7,2,'Устройство принято на диагностику',?)", (t,))


def init_db():
    path = app.config['DB']
    new = not os.path.exists(path)
    c = sqlite3.connect(path)
    c.execute('PRAGMA foreign_keys=ON')
    c.executescript(open(os.path.join(BASE, 'schema.sql'), encoding='utf-8').read())
    if new:
        seed(c)
    c.commit()
    c.close()


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
