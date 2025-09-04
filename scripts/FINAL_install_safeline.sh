#!/bin/bash

# =============================================================================
# Script d'Installation SafeLine WAF - Version Officielle Simple
# =============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# IPs
LOCAL_IP="192.168.142.141"    # SafeLine VM
NGINX_IP="192.168.142.128"    # NGINX VM
TARGET_IP="192.168.142.138"   # DVWA VM

print_status() {
    case $2 in
        "INFO") echo -e "${BLUE}[INFO]${NC} $1" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $1" ;;
        "WARNING") echo -e "${YELLOW}[WARNING]${NC} $1" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $1" ;;
        *) echo "$1" ;;
    esac
}

print_banner() {
    echo -e "${PURPLE}"
    echo "============================================================================="
    echo "                     INSTALLATION SAFELINE WAF - OFFICIELLE"
    echo "============================================================================="
    echo -e "${NC}"
    echo "VM SafeLine: $LOCAL_IP"
    echo "VM NGINX: $NGINX_IP"
    echo "VM Target (DVWA): $TARGET_IP"
    echo "============================================================================="
}

# Nettoyage complet
cleanup_safeline() {
    print_status "Nettoyage complet de SafeLine..." "INFO"
    
    # Arrêter tous les containers SafeLine
    docker stop $(docker ps -q --filter "name=safeline") 2>/dev/null || true
    docker rm $(docker ps -aq --filter "name=safeline") 2>/dev/null || true
    
    # Supprimer les images SafeLine
    docker rmi $(docker images | grep -E "(safeline|chaitin)" | awk '{print $3}') 2>/dev/null || true
    
    # Supprimer les répertoires
    rm -rf /data/safeline 2>/dev/null || true
    rm -rf /opt/safeline 2>/dev/null || true
    
    # Nettoyer les volumes Docker
    docker volume prune -f 2>/dev/null || true
    
    print_status "Nettoyage terminé" "SUCCESS"
}

# Installation officielle SafeLine
install_safeline_official() {
    print_status "Installation SafeLine avec la méthode officielle..." "INFO"
    
    print_status "Exécution de la commande officielle:" "INFO"
    echo "bash -c \"\$(curl -fsSLk https://waf.chaitin.com/release/latest/manager.sh)\" -- --en"
    echo ""
    
    print_status "IMPORTANT: Vous devrez interagir avec l'installateur:" "WARNING"
    echo "1. Appuyez sur ENTRÉE pour continuer"
    echo "2. Choisissez '1' pour INSTALL"
    echo "3. Entrez le chemin d'installation (par défaut: /data/safeline)"
    echo "4. Confirmez l'installation"
    echo ""
    
    read -p "Appuyez sur ENTRÉE pour lancer l'installation officielle..."
    
    # Lancer la commande officielle
    bash -c "$(curl -fsSLk https://waf.chaitin.com/release/latest/manager.sh)" -- --en
    
    if [ $? -eq 0 ]; then
        print_status "Installation officielle terminée" "SUCCESS"
        return 0
    else
        print_status "Échec de l'installation officielle" "ERROR"
        return 1
    fi
}

# Test des services
test_safeline_services() {
    print_status "Test des services SafeLine..." "INFO"
    
    # Attendre un peu que les services démarrent
    sleep 10
    
    # Vérifier les conteneurs
    print_status "État des conteneurs:" "INFO"
    docker ps --filter "name=safeline" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || {
        print_status "Aucun conteneur SafeLine trouvé" "WARNING"
        docker ps
        return 1
    }
    
    # Test des ports
    print_status "Test de connectivité..." "INFO"
    
    # Test port 9443 (HTTPS Management)
    if nc -z localhost 9443 2>/dev/null; then
        print_status "✓ Port 9443 (HTTPS Management): Ouvert" "SUCCESS"
    else
        print_status "✗ Port 9443: Fermé" "WARNING"
    fi
    
    # Test port 9080 (HTTP Proxy)  
    if nc -z localhost 9080 2>/dev/null; then
        print_status "✓ Port 9080 (HTTP Proxy): Ouvert" "SUCCESS"
    else
        print_status "✗ Port 9080: Fermé" "WARNING"
    fi
    
    # Test avec curl
    if curl -k -s --connect-timeout 5 https://localhost:9443 > /dev/null 2>&1; then
        print_status "✓ Interface HTTPS accessible" "SUCCESS"
    else
        print_status "⚠ Interface HTTPS non accessible (peut-être en cours de démarrage)" "WARNING"
    fi
}

# Configuration basique
configure_basic_setup() {
    print_status "Informations de configuration..." "INFO"
    
    cat << EOF

INFORMATIONS DE CONFIGURATION SAFELINE:
=====================================

1. Interface Web Management: https://$LOCAL_IP:9443
   - Première connexion: créez un compte administrateur
   
2. Interface Proxy: http://$LOCAL_IP:9080
   - Trafic filtré par le WAF

3. Pour protéger DVWA:
   - Connectez-vous à https://$LOCAL_IP:9443
   - Allez dans "Sites" > "Ajouter un site"
   - Nom: DVWA
   - Domaine: dvwa.local (ou votre domaine)
   - Serveur upstream: $TARGET_IP:80
   - Protocole: HTTP

4. Architecture:
   - Client → SafeLine WAF ($LOCAL_IP:9080) → DVWA ($TARGET_IP:80)

EOF
}

# Génération du rapport final
generate_final_report() {
    local report_file="/opt/safeline_installation_report.txt"
    
    cat > "$report_file" << EOF
=============================================================================
                    RAPPORT INSTALLATION SAFELINE WAF
=============================================================================

Date: $(date)
Serveur: $(hostname)
IP SafeLine: $LOCAL_IP

CONTENEURS DOCKER:
$(docker ps --filter "name=safeline" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Aucun conteneur SafeLine trouvé")

PORTS RÉSEAU:
$(netstat -tlnp 2>/dev/null | grep -E "(9080|9443)" || ss -tlnp | grep -E "(9080|9443)" || echo "Aucun port SafeLine détecté")

ACCÈS WEB:
- Interface Management: https://$LOCAL_IP:9443
- Interface Proxy: http://$LOCAL_IP:9080

CONFIGURATION DVWA:
- Target IP: $TARGET_IP
- Pour configurer: https://$LOCAL_IP:9443 > Sites > Ajouter un site
- Upstream: $TARGET_IP:80

COMMANDES UTILES:
- Status: docker ps | grep safeline
- Logs: docker logs safeline-luigi
- Redémarrer: cd /data/safeline && docker-compose restart

PROCHAINES ÉTAPES:
1. Accéder à https://$LOCAL_IP:9443
2. Créer un compte administrateur
3. Ajouter DVWA comme site protégé
4. Configurer les règles de sécurité

=============================================================================
EOF

    print_status "Rapport généré: $report_file" "SUCCESS"
}

# Fonction principale
main() {
    print_banner
    
    # Vérifier les privilèges root
    if [[ $EUID -ne 0 ]]; then
        print_status "Ce script doit être exécuté avec sudo" "ERROR"
        exit 1
    fi
    
    # Vérifier Docker
    if ! command -v docker &> /dev/null; then
        print_status "Docker n'est pas installé" "ERROR"
        exit 1
    fi
    
    # Vérifier curl
    if ! command -v curl &> /dev/null; then
        print_status "curl n'est pas installé" "ERROR"
        exit 1
    fi
    
    # Nettoyage préalable
    cleanup_safeline
    
    # Installation officielle
    if install_safeline_official; then
        print_status "Installation SafeLine réussie!" "SUCCESS"
    else
        print_status "Échec de l'installation SafeLine" "ERROR"
        exit 1
    fi
    
    # Tests
    test_safeline_services
    
    # Configuration
    configure_basic_setup
    
    # Rapport
    generate_final_report
    
    echo -e "\n${GREEN}============================================================================="
    echo "                    INSTALLATION SAFELINE TERMINÉE"
    echo "=============================================================================${NC}"
    echo ""
    echo "🎯 Accès SafeLine: https://$LOCAL_IP:9443"
    echo "📋 Rapport: /opt/safeline_installation_report.txt"
    echo ""
    
    print_status "Installation terminée avec succès!" "SUCCESS"
}

main "$@"
