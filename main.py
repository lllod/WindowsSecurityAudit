import requests
import win32evtlog
import win32evtlogutil
import winerror
import locale
from dotenv import load_dotenv
import os


def get_event_logs(server: str = None, logtype: str = 'Security') -> list:
    """
    Функция получает события из журнала (logtype) локальной Windows-системы, используя бибилиотеку pywin32.
    Возвращает список событий (events).
    """
    # !-- пометочка --! EvtOpenSession для открытие сессии на удаленной машине
    # total = win32evtlog.GetNumberOfEventLogRecords(hand)  # Всего событий в журнале

    try:
        hand = win32evtlog.OpenEventLog(server, logtype)  # Открытие журнала
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ  # определяем, как читать журнал
        events = win32evtlog.ReadEventLog(hand, flags, 0)  # читаем журнал
        return events
    except:
        print(f'Невозможно открыть журнал {logtype} на устройстве {server}')


def repeat(server: str = None, logtype: str = 'Security'):
    """
    Функция беспрерывного прохода по событям в журнале по заданным параметрам и вывода сообщения о новых событиях
    """
    ev_obj = [0] * 9
    logon_type_dict = {'2': 'Тип входа 2: Интерактивный', '10': 'Тип входа 10: RemoteInteractive'}
    admin_token_dict = {'%%1843': 'Учетная запись с правами пользователя',
                        '%%1842': 'Учетная запись с правами администратора'}
    while True:
        events = get_event_logs(server, logtype)  # Получаем события из журнала
        evt_query = [i for i in events if  # Параметры поиска по событиям
                     '4624' in str(winerror.HRESULT_CODE(i.EventID)) and (
                             (str(i.StringInserts[8])) == '2' or (str(i.StringInserts[8])) == '10')]
        for evt in evt_query:  # Вычленяем нужную информацию из события
            record_number = evt.RecordNumber
            admin_token = str(evt.StringInserts[-1])
            if record_number > ev_obj[-1] and admin_token == '%%1843':  # Выводим сообщения только о новых событиях
                time_generated = evt.TimeGenerated.Format('%d.%m.%Y (%A) %H:%M:%S')  # '12/23/99 15:54:09'
                event_id = evt.EventID
                computer_name = str(evt.ComputerName)
                target_username = str(evt.StringInserts[5])
                ip = str(evt.StringInserts[18])
                logon_type = str(evt.StringInserts[8])
                event_type = win32evtlogutil.SafeFormatMessage(evt, logtype).split('\r\n')[0]
                ev_obj = [time_generated, computer_name, target_username, ip, logon_type, admin_token, event_type,
                          event_id,
                          record_number]  # Сохраняем информацию о событии для последующего сравнения (может, не только)
                message = f'{ev_obj[6]} | {ev_obj[0]}\n' \
                          f'Пользователь {ev_obj[2]} авторизовался на {ev_obj[1]} с IP: {ev_obj[3]}\n' \
                          f'{logon_type_dict[logon_type]}'
                message_send(message)


def message_send(message: str):
    load_dotenv()
    bot_token = os.getenv('BOT_TOKEN')
    chat_id = os.getenv('CHAT_ID')

    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    payload = {'chat_id': chat_id, 'text': message}
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        raise Exception(f'Не удалось отправить сообщение: {response.text}')


if __name__ == "__main__":
    locale.setlocale(locale.LC_ALL, '')
    server = None  # None = локальная машина
    log_types = 'Security'  # 'System', 'Application'
    repeat(server, log_types)


# Реализовать вывод прав доступа учетной записи
# Реализовать вывод выхода из системы
