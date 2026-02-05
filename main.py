import re
from collections import defaultdict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

def load_log_source(source_path):
    """Ponto de entrada do sistema. Responsável por carregar os logs a partir do dataset"""
    raw_logs = []
    with open(source_path, 'r') as file:
        for line in file:
            raw_logs.append(line.strip())
    return raw_logs


def remove_log_header(log_line):
    """Remove o cabeçalho do log utilizando Regex.Remove timestamp, hostname e PID do processo sshd."""
    header_pattern = r'^[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+sshd\[\d+\]:\s+'
    return re.sub(header_pattern, '', log_line)


def normalize_log(log_line):
    """Normaliza o texto do log: remove símbolos e espaços em branco"""
    log_line = log_line.lower()
    log_line = re.sub(r'[^\w\s]', '', log_line)
    log_line = re.sub(r'\s+', ' ', log_line)
    return log_line.strip()


def tokenize_log(log_line):
    """
    Tokeniza o log utilizando expressões regulares,
    separando palavras relevantes.
    """
    tokens = re.findall(r'\w+', log_line)
    return tokens

#Novo método para extrair dados estruturados
def extract_event_data(log_line):
    """Extrai tipo de evento, usuário e IP"""
    user = None
    ip = None
    event_type = "unknown"

    user_match = re.search(r'user (\w+)', log_line)
    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log_line)

    if user_match:
        user = user_match.group(1)
    if ip_match:
        ip = ip_match.group(1)

    if "failed password" in log_line:
        event_type = "failed_login"
    elif "invalid user" in log_line:
        event_type = "invalid_user"
    elif "accepted password" in log_line:
        event_type = "successful_login"

    return {
        "event_type": event_type,
        "user": user,
        "ip": ip
    }

def preprocess_logs(raw_logs):
    """
    Pipeline completo de pré-processamento.
    Cada linha de log passa sequencialmente por:
    remoção do cabeçalho, normalização e tokenização.
    """
    structured_events = []

    for log in raw_logs:
        log_no_header = remove_log_header(log)
        normalized_log = normalize_log(log_no_header)
        tokens = tokenize_log(normalized_log)
        event_data= extract_event_data(normalized_log) # Extração de dados estruturados do evento

        structured_events.append({
            "original_log": log,
            "processed_log": normalized_log,
            "tokens": tokens,
            "event": event_data
        })

    return structured_events

#Método específico para detecção de ataques de força bruta
def detect_bruteforce(events, threshold=5):
    ip_failures = defaultdict(int)
    alerts = []

    for e in events:
        if e["event"]["event_type"] == "failed_login":
            ip = e["event"]["ip"]
            if ip:
                ip_failures[ip] += 1
                if ip_failures[ip] == threshold:
                    alerts.append(f"Força bruta detectada do IP {ip}")

    return alerts

#Método específico para detecção de ataques de enumeração de usuários
def detect_user_enumeration(events, threshold=3):
    ip_users = defaultdict(set)
    alerts = []

    for e in events:
        if e["event"]["event_type"] == "invalid_user":
            ip = e["event"]["ip"]
            user = e["event"]["user"]
            if ip and user:
                ip_users[ip].add(user)
                if len(ip_users[ip]) == threshold:
                    alerts.append(f"Enumeração de usuários detectada do IP {ip}")

    return alerts

#Método específico para detecção de login suspeito
def detect_suspicious_login(events, threshold=3):
    ip_failures = defaultdict(int)
    alerts = []

    for e in events:
        ip = e["event"]["ip"]
        if not ip:
            continue

        if e["event"]["event_type"] == "failed_login":
            ip_failures[ip] += 1

        if e["event"]["event_type"] == "successful_login":
            if ip_failures[ip] >= threshold:
                alerts.append(
                    f"Login suspeito do IP {ip} após {ip_failures[ip]} falhas"
                )

    return alerts

#Método novo para veotrização
def vectorize_logs(events):
    """ Converte logs em vetores numéricos usando TF-IDF. """
    texts = [e["processed_log"] for e in events]
    vectorizer = TfidfVectorizer()
    vectors = vectorizer.fit_transform(texts)
    return vectors

#Método que integra IA na detecção de problemas
def detect_anomalies(vectors, eps=0.8, min_samples=5):
    """Aplica DBSCAN para identificar padrões e anomalias."""
    model = DBSCAN(eps=eps, min_samples=min_samples, metric="cosine")
    labels = model.fit_predict(vectors)
    return labels

def apply_analysis(events):
    """Integra o agente de IA e identifica eventos anômalos"""
    vectors = vectorize_logs(events)
    labels = detect_anomalies(vectors)

    count = 0

    for idx, label in enumerate(labels):
        if label == -1:
            count += 1

    return count


# Método novo que gera templates de logs para análises
def generate_templates(events):
    templates = defaultdict(int)

    for e in events:
        template = re.sub(r'\d+\.\d+\.\d+\.\d+', '<IP>', e["processed_log"])
        template = re.sub(r'user \w+', 'user <USER>', template)
        templates[template] += 1

    return templates

def status (bruteforce_alerts, enumeration_alerts, suspicious_alerts, count ):
     

    if bruteforce_alerts:
        print(f"[ALERTA] {len(bruteforce_alerts)} indício de força bruta detectado.")

    if enumeration_alerts:
        print(f"[ALERTA] {len(enumeration_alerts)} indício de enumeração de usuários.")

    if suspicious_alerts:
        print(f"[ALERTA] {len(suspicious_alerts)} login suspeito após falhas.")

    if count > 0:
        print("[ALERTA - IA] Possível comportamento anômalo identificado pelo agente de IA.")
        print(f"Eventos anômalos detectados: {count}")
    else:
        print("Nenhum comportamento relevante detectado.")

    if (
        bruteforce_alerts
        or enumeration_alerts
        or suspicious_alerts
        or count > 0
    ):
        print("\nindícios de possíveis ataques ou atividades suspeitas.")
    else:
        print("\nNenhuma atividade suspeita relevante foi detectada.")




def main():
    raw_logs = load_log_source("SSH.log/dataset.log")

    # Pré-processamento
    events = preprocess_logs(raw_logs)

    # Heurísticas
    bruteforce_alerts = detect_bruteforce(events)
    enumeration_alerts = detect_user_enumeration(events)
    suspicious_alerts = detect_suspicious_login(events)

    events_test = events[:1000]
    count = apply_analysis(events_test)

    status(
        bruteforce_alerts,
        enumeration_alerts,
        suspicious_alerts,
        count
    )
 
if __name__ == "__main__":
    main()