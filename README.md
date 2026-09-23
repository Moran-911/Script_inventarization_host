# Скрипт инвентаризации хостов
Предназначен для пассивного сканирования состояния хоста в нашей корпоративной сети, показывает, какие сетевые порты открыты + версии сетевых протоколах, которые как раз таки расположены на этих открытых портах. В перспективе можно написать в скрипте функцию пассивного сканирования для более полного понимания, какие возможные атаки можно провести на наш хост для закрытия этих уяз. Ну а теперь давайте приступим к разбору полетов (конкретно к нашему программному коду).

# Для начала дайте рассмотрим библиотеки, которые мы импортировали для дальнейшей работы нашей программы:

import socket - для создания сокетов , т.е подключения между нашим и удаленным хостом, который мы хотим просканировать
import logging - для просмотра логов
from datetime import datetime - для фиксации времени начала и конца сканирования для подсчета общего вермени работы
import ssl - для создания безопасной оболочки ssl для того, чтобы программа нам выводила версии web-серверов, если запросы\n от сервера у нас принимаются по протоколу https
import re - для работы с регулярными выражениями

# Далее задаем базовый формат вывода нашего лога:

logging.basicConfig(level=logging.INFO, format="%(message)s") # выводит информационные сообщения формата message

# Тут мы вводим либо доменное имя, либо ip-адрес хоста, который мы хоти просканировать

host_target = input("Введите ip-адрес хоста или его доменное имя: ")

# Составляем список популярных сетевых портов (PS: этот список словарей можно расширять сколько нашей душе угодно)
POPULAR_PORTS = 
    
    [#Веб
    {"port": 80, "name": "HTTP", "protocol": "TCP", "description": "Передача веб-страниц (незащищенный)"},
    {"port": 443, "name": "HTTPS", "protocol": "TCP", "description": "Защищенная передача веб-страниц (SSL/TLS)"},
    {"port": 8080, "name": "HTTP-Alt", "protocol": "TCP", "description": "Альтернативный HTTP (часто прокси, Tomcat)"},
    {"port": 8443, "name": "HTTPS-Alt", "protocol": "TCP", "description": "Альтернативный HTTPS"},
    #Передача файлов
    {"port": 20, "name": "FTP-Data", "protocol": "TCP", "description": "Передача данных по FTP"},
    {"port": 21, "name": "FTP-Control", "protocol": "TCP", "description": "Управление FTP-сессией"},
    {"port": 22, "name": "SSH / SFTP", "protocol": "TCP", "description": "Безопасный удаленный доступ и передача файлов"},
    {"port": 69, "name": "TFTP", "protocol": "UDP", "description": "Тривиальный FTP (прошивки, загрузка по сети)"},
    #Электронная почта
    {"port": 25, "name": "SMTP", "protocol": "TCP", "description": "Отправка почты (между серверами)"},
    {"port": 110, "name": "POP3", "protocol": "TCP", "description": "Получение почты (с удалением с сервера)"},
    {"port": 143, "name": "IMAP", "protocol": "TCP", "description": "Получение почты (синхронизация с сервером)"},
    {"port": 465, "name": "SMTPS", "protocol": "TCP", "description": "Защищенная отправка почты (SSL)"},
    {"port": 587, "name": "SMTP-Submission", "protocol": "TCP", "description": "Отправка почты от клиента (STARTTLS)"},
    {"port": 993, "name": "IMAPS", "protocol": "TCP", "description": "Защищенный IMAP (SSL)"},
    {"port": 995, "name": "POP3S", "protocol": "TCP", "description": "Защищенный POP3 (SSL)"},
    #Удаленный доступ
    {"port": 23, "name": "Telnet", "protocol": "TCP", "description": "Незащищенный удаленный доступ (устарел)"},
    {"port": 3389, "name": "RDP", "protocol": "TCP/UDP", "description": "Удаленный рабочий стол Windows"},
    {"port": 5900, "name": "VNC", "protocol": "TCP", "description": "Виртуальный сетевой компьютер (удаленный экран)"},
    #Базы данных
    {"port": 3306, "name": "MySQL / MariaDB", "protocol": "TCP", "description": "Подключение к базе данных MySQL"},
    {"port": 5432, "name": "PostgreSQL", "protocol": "TCP", "description": "Подключение к базе данных PostgreSQL"},
    {"port": 1433, "name": "MS SQL", "protocol": "TCP", "description": "Microsoft SQL Server"},
    {"port": 1521, "name": "Oracle DB", "protocol": "TCP", "description": "Oracle Database"},
    {"port": 27017, "name": "MongoDB", "protocol": "TCP", "description": "NoSQL база данных MongoDB"},
    {"port": 6379, "name": "Redis", "protocol": "TCP", "description": "Хранилище ключ-значение в памяти"},
    # Инфраструктура и сеть
    {"port": 53, "name": "DNS", "protocol": "TCP/UDP", "description": "Преобразование доменных имен в IP"},
    {"port": 67, "name": "DHCP-Server", "protocol": "UDP", "description": "Выдача IP-адресов (сервер)"},
    {"port": 68, "name": "DHCP-Client", "protocol": "UDP", "description": "Получение IP-адресов (клиент)"},
    {"port": 123, "name": "NTP", "protocol": "UDP", "description": "Синхронизация времени"},
    {"port": 161, "name": "SNMP", "protocol": "UDP", "description": "Мониторинг сетевого оборудования"},
    {"port": 389, "name": "LDAP", "protocol": "TCP", "description": "Доступ к службам каталогов (Active Directory)"},
    {"port": 636, "name": "LDAPS", "protocol": "TCP", "description": "Защищенный LDAP (SSL/TLS)"},
    {"port": 514, "name": "Syslog", "protocol": "UDP", "description": "Системные логи (передача)"},
    # Прочее
    {"port": 1900, "name": "SSDP", "protocol": "UDP", "description": "Обнаружение устройств (UPnP)"},
    {"port": 5353, "name": "mDNS", "protocol": "UDP", "description": "Мультикаст DNS (Bonjour, Avahi)"},
     # Windows
    {"port": 135, "name": "MS-RPC", "description": "Диспетчер удаленного вызова процедур Windows"},
    {"port": 139, "name": "NetBIOS-SSN", "description": "Служба сессий NetBIOS"},
    {"port": 445, "name": "SMB", "description": "Общие папки и принтеры Windows (Файловый доступ)"},
    {"port": 3389, "name": "RDP", "description": "Удаленный рабочий стол Windows"},
    {"port": 5985, "name": "WinRM (HTTP)", "description": "Удаленное управление PowerShell"},
    {"port": 5986, "name": "WinRM (HTTPS)", "description": "Защищенное удаленное управление PowerShell"}]

# порты на которых расположен http
HTTP_PORTS=[80, 8080]
# порты на которых расположен https
PS: Это разделение необходимо для дальнейшей работы, чтобы если мы работали с http, он создавал обычный сокет, а если https, то мы создаем сокет с так называемой ssl оболочкой для безопасного подключения.

SSL_HTTP_PORTS=[443, 8443]

# Создаем контекст SSL

Мы обозначаем при помощи параметра ssl.PROTOCOL_TLS_CLIENT, что мы клиент и мы подключаемся к серверу по TLS:
ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

# Отключаем проверку сертификата, т.к. мы должны сканировать порты

ssl_context.check_hostname=False 

ssl_context.verify_mode=ssl.CERT_NONE
# В список оnly_ports из списка POPULAR_PORTS записываем только ключ port:

only_ports = [item["port"] for item in POPULAR_PORTS]
print("Список портов для сканирования:", only_ports)

# При помощи socket.gethostbyname переводи доменное имя хоста в ip-адрес при необходимости, если же мы вводи ip-адрес, то эта встроенная функция тоже работает корректно.

try:
    target_ip = socket.gethostbyname(host_target)
    logging.info(f"Начинаем сканирование хоста: {host_target} ({target_ip})")
    logging.info("-" * 50)
    
# Фиксируем время работы начала сканирования при помощи datetime.now()    

    start_time = datetime.now()
    
# Циклом for проходим по всем портам из списка и создаем сокет 
Важный момент: указываем параметр socket.AF_INET для работы c ipv4 и socket.SOCK_STREAM для работы с протоколом tcp) и пихаем это все в переменную sock

    for target_port in only_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
Ждем 2 секунды для подключения       

            sock.settimeout(2.0)
            
# sock.connect_ex позволяет вывести стату подключения по целевому ip-адресу + целевому порту

PS: При выводе 0 означает, что подключение выполнено успешно

            result = sock.connect_ex((target_ip, target_port))          
            if result == 0:
                service_info = "нет данных"
                try:
                
# Чрез socket.getservbyport получаем информацию о сервисе (сетевом протоколе), расположенные на целевом порту  

                    service_info = socket.getservbyport(target_port, 'tcp')                    
                except OSError:
                    pass
                    
Далее создаем переменную banner для записи в нее версии web-сервера      

                banner = ""
sock.recv(1024) обозначает сколько байтс вернет сервер при успешном принятии запроса               
                try:
                    banner_bytes = sock.recv(1024)
                    
Если он что-то вернул, то декодирует эту всю шнягу в привычный для нас формат utf-8 и при помощи strip() удаляем в выводе пробельные символы   

                    if banner_bytes:
                        banner = banner_bytes.decode('utf-8', errors='ignore').strip() 
                except socket.timeout:
                    pass
                
# Сбор инфы о версии веб сервера:

Важно уточнение, здесь мы проходи по портам 80 и 8080, одним словом незащищенный протокол http, у которого нет ssl оболочки

                if not banner and target_port in HTTP_PORTS:
                    try:
                    
Создаем сокет и запихиваем это все в переменную http_sock    

                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as http_sock:
                            http_sock.settimeout(2.0)
                            
Проверяем успешность подключения (если статус подключения - 0, значит все круто)   

                            if http_sock.connect_ex((target_ip, target_port)) == 0:
                            
в переменную req записываем форму запроса которую мы отправляем на хост, в нашем случае указываем в хэдере host: {"наш целевой ip и user-agent: Scanner/1.0"} 

                                req = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Scanner/1.0\r\n\r\n"
                                
Через http_sock.sendall(req.encode('utf-8')) отправляем запрос    

                                http_sock.sendall(req.encode('utf-8'))
                                
И получаем ответ от сервера в размере 1024 байт      

                                res = http_sock.recv(1024).decode('utf-8', errors='ignore')
                                for line in res.split("\r\n"):
                                    if line.lower().startswith("server:"):
                                        banner = line.strip()
                                        break
                    except Exception:
                        pass
                        
Проворачиваем те же действия что и в прошлом блоке кода, за исключением того, что мы это все заворачиваем в контекст ssl (создаем безопасное соединение),  для того чтобы сканер успешно грабил версию web-сервера если запросы передаются не в открытом виде, а по защищенному протоколу https:

                elif not banner and target_port in SSL_HTTP_PORTS:
                    try:
                        base_sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        base_sock.settimeout(2.5)
                        with ssl_context.wrap_socket(base_sock, server_hostname=None) as secure_sock:
                            if secure_sock.connect_ex((target_ip, target_port)) == 0:
                                req = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: SSLScanner/1.0\r\n\Connection: close\r\n\r\n"
                                secure_sock.sendall(req.encode('utf-8'))
                                res = secure_sock.recv(1024).decode('utf-8', errors='ignore')
                                                        
                                                       
                                for line in res.split("\r\n"):
                                    if line.lower().startswith("server:"):
                                        banner = line.replace("Server:","").strip()+" (HTTPS/SSL)"
                                        break
                                if not banner and res:
                                    banner=res.split("\r\n")[0].strip()+" (SSL Service Banner)"       
                    except Exception:
                        pass    
                if banner:
                    logging.info(f"Порт {target_port: <5} [ОТКРЫТ]  -> Сервис: {service_info} | Подробно: {banner}")
                else:
                    logging.info(f"Порт {target_port: <5} [ОТКРЫТ]  -> Сервис: {service_info} (Баннер не получен)")
            else:
                logging.debug(f"Порт {target_port} закрыт или отфильтрован.")
                
 # Фиксируем конец работы сканера
 
    end_time = datetime.now()
    logging.info("-" * 50)
    
  Подсчитываем разнице между концом и началом работы, чтобы вычислить общее время работы  
  
    logging.info(f"Сканирование завершено за: {end_time - start_time}")
except socket.gaierror:
    logging.error("Ошибка: Не удалось разрешить имя хоста (проверьте DNS или интернет).")
except KeyboardInterrupt:
    logging.warning("\nСканирование прервано пользователем.")



