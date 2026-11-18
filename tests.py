import io, os, tempfile, time, unittest
import app as A


def png():
    return (io.BytesIO(b'\x89PNG\r\n\x1a\n' + b'0' * 50), 'photo.png')


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        A.app.config.update(DB=os.path.join(self.tmp, 't.db'), UPLOADS=os.path.join(self.tmp, 'up'), TESTING=True)
        A.init_db()
        self.c = A.app.test_client()

    def login(self, email, pw, client=None):
        return (client or self.c).post('/login', data={'email': email, 'password': pw}, follow_redirects=True)

    def as_(self, role):
        cr = {'admin': ('admin@shop.ru', 'admin123'), 'master': ('master@shop.ru', 'master123'), 'client': ('client@shop.ru', 'client123')}[role]
        c = A.app.test_client()
        self.login(*cr, client=c)
        return c

    def q(self, sql, a=()):
        with A.app.app_context():
            return [tuple(r) for r in A.q(sql, a)]


class TestAuth(Base):
    def reg(self, **o):
        d = dict(name='Тест Тестов', email='new@mail.ru', phone='+79001112233', password='secret1', password2='secret1')
        d.update(o)
        return self.c.post('/register', data=d, follow_redirects=True).get_data(as_text=True)

    def test_register_ok_and_hashed(self):
        self.assertIn('Регистрация прошла успешно', self.reg())
        h = self.q('SELECT password_hash FROM users WHERE email=?', ('new@mail.ru',))[0][0]
        self.assertNotIn('secret1', h)
        self.assertTrue(h.startswith(('pbkdf2', 'scrypt')))

    def test_register_bad_email(self):
        self.assertIn('Некорректный e-mail', self.reg(email='abc'))

    def test_register_short_password_boundary(self):
        self.assertIn('Пароль: от 6', self.reg(password='12345', password2='12345'))
        self.assertIn('Регистрация прошла успешно', self.reg(password='123456', password2='123456'))

    def test_register_mismatch(self):
        self.assertIn('Пароли не совпадают', self.reg(password2='other11'))

    def test_register_duplicate(self):
        self.reg()
        self.assertIn('уже зарегистрирован', self.reg())

    def test_register_bad_phone(self):
        self.assertIn('Телефон', self.reg(phone='123'))

    def test_login_ok_wrong_and_sqli(self):
        self.assertIn('Мои заявки', self.login('client@shop.ru', 'client123').get_data(as_text=True))
        self.assertIn('Неверный', self.login('client@shop.ru', 'bad').get_data(as_text=True))
        self.assertIn('Неверный', self.login("' OR '1'='1' --", "' OR '1'='1").get_data(as_text=True))

    def test_logout(self):
        c = self.as_('client')
        c.get('/logout')
        self.assertEqual(c.get('/cabinet').status_code, 302)


class TestAccess(Base):
    def test_public_pages(self):
        for u in ['/', '/login', '/register', '/track']:
            self.assertEqual(self.c.get(u).status_code, 200, u)

    def test_anonymous_redirect(self):
        for u in ['/cabinet', '/request/new', '/master', '/admin', '/admin/stats', '/request/1']:
            self.assertEqual(self.c.get(u).status_code, 302, u)

    def test_client_forbidden(self):
        c = self.as_('client')
        for u in ['/admin', '/admin/users', '/admin/parts', '/admin/services', '/admin/stats', '/master']:
            self.assertEqual(c.get(u).status_code, 403, u)

    def test_master_forbidden(self):
        c = self.as_('master')
        for u in ['/admin', '/admin/users', '/cabinet']:
            self.assertEqual(c.get(u).status_code, 403, u)

    def test_all_pages_for_roles(self):
        for u in ['/cabinet', '/request/new', '/request/8', '/request/8/receipt']:
            self.assertEqual(self.as_('client').get(u).status_code, 200, u)
        for u in ['/master', '/request/1']:
            self.assertEqual(self.as_('master').get(u).status_code, 200, u)
        for u in ['/admin', '/admin/services', '/admin/users', '/admin/parts', '/admin/stats', '/request/1', '/request/1/receipt']:
            self.assertEqual(self.as_('admin').get(u).status_code, 200, u)

    def test_master_other_request_forbidden(self):
        self.assertEqual(self.as_('master').get('/request/6').status_code, 403)

    def test_client_other_request_forbidden(self):
        self.c.post('/register', data=dict(name='Иван', email='i@m.ru', phone='+79005556677', password='123456', password2='123456'))
        c = A.app.test_client()
        self.login('i@m.ru', '123456', client=c)
        self.assertEqual(c.get('/request/1').status_code, 403)

    def test_404(self):
        self.assertEqual(self.as_('admin').get('/request/9999').status_code, 404)

    def test_response_time(self):
        c = self.as_('admin')
        for u in ['/', '/admin', '/admin/stats']:
            t = time.time()
            c.get(u)
            self.assertLess(time.time() - t, 2, u)


class TestRequests(Base):
    def new(self, **o):
        d = dict(device='Смартфон', model='iPhone 12', fault='Не включается', problem='Телефон не включается после падения')
        d.update(o)
        if 'photo' not in d:
            d['photo'] = png()
        return self.as_('client').post('/request/new', data=d, content_type='multipart/form-data', follow_redirects=True).get_data(as_text=True)

    def test_create_with_photo(self):
        self.assertIn('Заявка №9 создана', self.new())
        self.assertTrue(os.listdir(os.path.join(self.tmp, 'up')))

    def test_problem_length_boundaries(self):
        self.assertIn('от 10 до 1000', self.new(problem='x' * 9))
        self.assertIn('создана', self.new(problem='x' * 10))
        self.assertIn('создана', self.new(problem='x' * 1000))
        self.assertIn('от 10 до 1000', self.new(problem='x' * 1001))

    def test_bad_extension(self):
        self.assertIn('допустимы только', self.new(photo=(io.BytesIO(b'MZ'), 'virus.exe')))

    def test_file_too_big(self):
        r = self.as_('client').post('/request/new', data=dict(device='Смартфон', model='X1', fault='Не включается', problem='Описание неисправности', photo=(io.BytesIO(b'0' * (5 * 1024 * 1024 + 10)), 'a.png')), content_type='multipart/form-data')
        self.assertEqual(r.status_code, 413)

    def test_invalid_device(self):
        self.assertIn('Выберите тип устройства', self.new(device='Холодильник'))

    def test_no_photo_ok(self):
        self.assertIn('создана', self.new(photo=(io.BytesIO(b''), '')))

    def test_sqli_in_model_stored_safely(self):
        self.new(model="x'); DROP TABLE users;--")
        self.assertEqual(len(self.q('SELECT id FROM users')), 4)

    def test_xss_escaped(self):
        out = self.new(problem='<script>alert(1)</script> длинный текст')
        self.assertNotIn('<script>alert(1)</script>', out)

    def test_cabinet_shows_status(self):
        self.assertIn('Принята', self.as_('client').get('/cabinet').get_data(as_text=True))

    def test_track(self):
        r = self.c.post('/track', data={'id': '1', 'phone': '4567'}).get_data(as_text=True)
        self.assertIn('Статус:', r)
        r = self.c.post('/track', data={'id': '1', 'phone': '0000'}).get_data(as_text=True)
        self.assertIn('не найдена', r)
        r = self.c.post('/track', data={'id': "1' OR 1=1", 'phone': '4567'}).get_data(as_text=True)
        self.assertIn('не найдена', r)


class TestMaster(Base):
    def post(self, **d):
        return self.as_('master').post('/request/1', data=d, follow_redirects=True).get_data(as_text=True)

    def test_status_change(self):
        self.assertIn('Статус обновлён', self.post(action='status', status='В ремонте'))
        self.assertEqual(self.q('SELECT status FROM requests WHERE id=1')[0][0], 'В ремонте')

    def test_invalid_status(self):
        self.assertIn('Недопустимый статус', self.post(action='status', status='Взлом'))

    def test_comment_boundaries(self):
        self.assertIn('от 1 до 500', self.post(action='comment', text=''))
        self.assertIn('от 1 до 500', self.post(action='comment', text='x' * 501))
        self.post(action='comment', text='x' * 500)
        self.assertEqual(len(self.q('SELECT id FROM comments WHERE request_id=1')), 1)

    def test_cost_boundaries(self):
        for v, ok in [('-1', 0), ('0', 1), ('1000000', 1), ('1000001', 0), ('abc', 0), ('nan', 0), ('inf', 0)]:
            out = self.post(action='cost', work_cost=v)
            self.assertEqual('сохранена' in out, bool(ok), v)

    def test_part_deducts_stock(self):
        before = self.q('SELECT quantity FROM parts WHERE id=2')[0][0]
        self.assertIn('Запчасть добавлена', self.post(action='part', part_id='2', qty='2'))
        self.assertEqual(self.q('SELECT quantity FROM parts WHERE id=2')[0][0], before - 2)

    def test_part_boundaries(self):
        self.assertIn('от 1 до 1000', self.post(action='part', part_id='2', qty='0'))
        self.assertIn('На складе только', self.post(action='part', part_id='3', qty='3'))
        self.assertIn('добавлена', self.post(action='part', part_id='3', qty='2'))
        self.assertIn('На складе только 0', self.post(action='part', part_id='3', qty='1'))

    def test_client_cannot_change_status(self):
        c = self.as_('client')
        c.post('/request/8', data={'action': 'status', 'status': 'Выдана'})
        self.assertEqual(self.q('SELECT status FROM requests WHERE id=8')[0][0], 'Принята')


class TestAdmin(Base):
    def setUp(self):
        super().setUp()
        self.a = self.as_('admin')

    def test_assign(self):
        self.a.post('/admin/assign', data={'id': '8', 'master_id': '3'})
        self.assertEqual(self.q('SELECT master_id FROM requests WHERE id=8')[0][0], 3)

    def test_assign_non_master_rejected(self):
        self.assertEqual(self.a.post('/admin/assign', data={'id': '8', 'master_id': '4'}).status_code, 400)

    def test_kanban_api(self):
        r = self.a.post('/api/status', json={'id': 8, 'status': 'В ремонте'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.a.post('/api/status', json={'id': 8, 'status': 'x'}).status_code, 400)
        self.assertEqual(self.as_('client').post('/api/status', json={'id': 8, 'status': 'Выдана'}).status_code, 403)

    def test_services_crud(self):
        self.a.post('/admin/services', data=dict(action='add', name='Тест', description='', price_from='100', price_to='200'))
        self.assertEqual(len(self.q("SELECT id FROM services WHERE name='Тест'")), 1)
        out = self.a.post('/admin/services', data=dict(action='add', name='Плохая', description='', price_from='500', price_to='100'), follow_redirects=True).get_data(as_text=True)
        self.assertIn('Проверьте поля', out)
        sid = self.q("SELECT id FROM services WHERE name='Тест'")[0][0]
        self.a.post('/admin/services', data=dict(action='delete', id=str(sid)))
        self.assertEqual(len(self.q("SELECT id FROM services WHERE name='Тест'")), 0)

    def test_add_staff_and_login(self):
        self.a.post('/admin/users', data=dict(action='add', name='Новый Мастер', email='nm@shop.ru', phone='+79007778899', password='master99', role='master'))
        self.assertIn('Рабочее место', self.login('nm@shop.ru', 'master99', client=A.app.test_client()).get_data(as_text=True))

    def test_block_user(self):
        self.a.post('/admin/users', data=dict(action='update', id='4', role='client', active='0'))
        self.assertIn('Неверный', self.login('client@shop.ru', 'client123', client=A.app.test_client()).get_data(as_text=True))

    def test_cannot_edit_self(self):
        out = self.a.post('/admin/users', data=dict(action='update', id='1', role='client', active='1'), follow_redirects=True).get_data(as_text=True)
        self.assertIn('Нельзя изменить', out)

    def test_parts_crud_and_limits(self):
        self.a.post('/admin/parts', data=dict(action='add', name='Шлейф', sku='FLX-1', quantity='5', min_qty='1', price='300'))
        self.assertEqual(len(self.q("SELECT id FROM parts WHERE sku='FLX-1'")), 1)
        out = self.a.post('/admin/parts', data=dict(action='add', name='Шлейф2', sku='FLX-1', quantity='5', min_qty='1', price='300'), follow_redirects=True).get_data(as_text=True)
        self.assertIn('Артикул уже существует', out)
        out = self.a.post('/admin/parts', data=dict(action='update', id='1', quantity='-1', price='10'), follow_redirects=True).get_data(as_text=True)
        self.assertIn('неотрицательные', out)
        out = self.a.post('/admin/parts', data=dict(action='delete', id='1'), follow_redirects=True).get_data(as_text=True)
        self.assertIn('удалить нельзя', out)

    def test_low_stock_flag(self):
        self.assertIn('мало', self.a.get('/admin/parts').get_data(as_text=True))

    def test_stats_content(self):
        out = self.a.get('/admin/stats').get_data(as_text=True)
        for s in ['Заявки по месяцам', 'Доход', 'Популярные неисправности', 'Загрузка мастеров']:
            self.assertIn(s, out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
