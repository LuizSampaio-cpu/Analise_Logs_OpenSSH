
import re
from collections import defaultdict, Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

def load_logs(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()

# ----------------------

# Novo método para normalizar e estruturar os logs para análise, substituindo os métodos da entrega anterior remove_log_header(), normalize_log() e tokenize_log().
# Além disso, o método extract_event_data() também agora está incluso no regex, ou seja, não é mais necessário.

# ----------------------
def preprocess_logs(raw_logs):
    events = []
    pattern = re.compile(
        r"(?P<event>Failed password|Accepted password|Invalid user).*?(?P<user>\w+).*?from\s(?P<ip>\d+\.\d+\.\d+\.\d+)",
        re.IGNORECASE
    )

    for line in raw_logs:
        match = pattern.search(line)
        if match:
            events.append({
                "raw": line.strip(),
                "event": match.group("event").lower(),
                "user": match.group("user"),
                "ip": match.group("ip")
            })

    return events

#-------------------

# Para facilitar análise e simplificar o código, o novo método detect_heuristics() reúne as análises que antes se encontravam nos métodos de 
# detect_brute_force(), detect_user_enumeration() e detect_suspicious_login(), os quais analisavam, respectivamente:
# tentativas de força bruta, tentativas de enumeração de usuários e tentativas de login suspeitos.

#-------------------

def detect_heuristics(events):
    alerts = []
    ip_failures = defaultdict(int)
    ip_users = defaultdict(set)

    for e in events:
        if "failed" in e["event"]:
            ip_failures[e["ip"]] += 1
        if "invalid" in e["event"]:
            ip_users[e["ip"]].add(e["user"])

    for ip, count in ip_failures.items():
        if count >= 5:
            alerts.append(f"Força bruta detectada do IP {ip} ({count} falhas)")

    for ip, users in ip_users.items():
        if len(users) >= 3:
            alerts.append(f"Enumeração de usuários detectada do IP {ip}")

    return alerts

# -----------------

# O método de ai_analysis() agora realiza também a função do método anterior de vetorização dos logs (vectorize_logs()), que agora implementa
# o TfidfVectorizer() para realizar tal ação. Além disso, o antigo método de detecção de anomalias (detect_anomalies()) também teve sua funcionalidade
# absorvida pelo método de análise abaixo.

# -----------------
def ai_analysis(events):
    texts = [f"{e['event']} {e['user']} {e['ip']}" for e in events]

    vectorizer = TfidfVectorizer()
    vectors = vectorizer.fit_transform(texts)

    model = DBSCAN(metric="cosine", eps=0.5, min_samples=5)
    labels = model.fit_predict(vectors)

    anomalies = [e for e, l in zip(events, labels) if l == -1]
    return anomalies

# -------------------

# Os métodos anteriores para exibição do status de análise e e aplicação da mesma não são mais necessários (status() e apply_analysis()). O novo método de geração do
# relatório (generate_report()) é agora o responsável por isso. Ou seja, pegar o resultado da análise pelo agente e gerar um arquivo de relatório para o usuário 
# conseguir entender a análise feita pelo programa, não sendo mais exibido apenas no console de execução.

# -------------------

def generate_templates(events):
    templates = Counter()
    for e in events:
        templates[f"{e['event']} for USER from IP"] += 1
    return templates

def generate_report(events, alerts, anomalies, templates):
    with open("relatorio_final.txt", "w", encoding="utf-8") as f:
        f.write("RELATÓRIO – ANÁLISE DE LOGS OPENSSH\n\n")

        f.write("Exemplos de logs processados:\n")
        for e in events[:5]:
            f.write(f"- {e['raw']}\n")

        f.write("\nTemplates gerados:\n")
        for t, c in templates.items():
            f.write(f"- {t} ({c})\n")

        f.write("\nEventos detectados:\n")
        for a in alerts:
            f.write(f"- {a}\n")

        f.write("\nEventos anômalos (IA):\n")
        for a in anomalies[:5]:
            f.write(f"- {a}\n")


def main():
    raw_logs = load_logs("SSH.log/SSH.log")
    events = preprocess_logs(raw_logs)

    alerts = detect_heuristics(events)
    anomalies = ai_analysis(events[:1000])
    templates = generate_templates(events)

    generate_report(events, alerts, anomalies, templates)

    print("Análise concluída. Relatório gerado.")


if __name__ == "__main__":
    main()
