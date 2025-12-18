import re

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

        structured_events.append({
            "original_log": log,
            "processed_log": normalized_log,
            "tokens": tokens
        })

    return structured_events


def analyze_events(structured_events):
    """
    Etapa de análise inicial.
    Os eventos já estão estruturados e prontos para
    evolução futura (clusterização, IA, etc.).
    """
    alerts = []

    for event in structured_events:
        tokens = event["tokens"]

        if "failed" in tokens and "password" in tokens:
            alerts.append("Possível tentativa de força bruta")

        if "invalid" in tokens and "user" in tokens:
            alerts.append("Possível enumeração de usuários")

    return alerts


def main():
    """
    Função principal que demonstra o fluxo completo
    de entrada dos logs até a análise preliminar.
    """
    log_file_path = "auth.log"  # arquivo ou dataset de logs
    raw_logs = load_log_source(log_file_path)

    structured_events = preprocess_logs(raw_logs)

    alerts = analyze_events(structured_events)

    return alerts
