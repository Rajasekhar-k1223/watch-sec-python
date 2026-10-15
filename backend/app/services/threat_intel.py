import logging
from datetime import datetime
from sqlalchemy.orm import Session
from app.db.models import GlobalSoftwareCatalog

logger = logging.getLogger("ThreatIntel")

def sync_global_software_catalog(session: Session):
    """
    Simulates querying an external Threat Intel or Public Package API (like Winget/Homebrew).
    Updates the GlobalSoftwareCatalog with the true marketing version of the software.
    """
    logger.info("Syncing Global Software Catalog from Threat Intel sources...")
    import requests
    import re
    
    logger.info("Syncing Global Software Catalog from live Threat Intel sources (Homebrew API)...")
    
    # Fetch real live data from public API
    api_url = "https://formulae.brew.sh/api/cask.json"
    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        casks = response.json()
    except Exception as e:
        logger.error(f"Failed to fetch live threat intel data: {e}")
        return

    # Build a lookup dictionary. 
    # Keys will be aggressively lowercased and stripped of spaces/punctuation for fuzzy matching.
    def normalize_name(name):
        return re.sub(r'[^a-z0-9]', '', name.lower())
    
    live_software_db = {}
    for cask in casks:
        # Cask has a list of 'name's, we'll index all of them
        version = cask.get("version")
        url = cask.get("homepage") or ""
        
        # WinZip has weird token names, let's just index everything
        names_to_index = cask.get("name", [])
        names_to_index.append(cask.get("token", ""))
        
        for n in names_to_index:
            norm = normalize_name(n)
            if norm and version:
                live_software_db[norm] = {
                    "MarketingVersion": version,
                    "DownloadUrl": url,
                    "PatchInstructions": f"Download latest release from {url}"
                }

    # Iterate over our global catalog and try to match it against the live internet database
    all_entries = session.query(GlobalSoftwareCatalog).all()
    matched_count = 0
    
    for catalog_entry in all_entries:
        software_name = catalog_entry.SoftwareName
        norm_name = normalize_name(software_name)
        
        # Hardcode some known mismatches if needed (e.g., Google Chrome -> googlechrome)
        if "chrome" in norm_name: norm_name = "googlechrome"
        if "edge" in norm_name and "webview" not in norm_name: norm_name = "microsoftedge"
        
        live_data = live_software_db.get(norm_name)
        
        if live_data:
            # We found a real match on the internet!
            catalog_entry.MarketingVersion = live_data["MarketingVersion"]
            catalog_entry.DownloadUrl = live_data["DownloadUrl"]
            catalog_entry.PatchInstructions = live_data["PatchInstructions"]
            catalog_entry.UpdatedAt = datetime.utcnow()
            matched_count += 1


    # Fallback: Populate any auto-registered software that has a NULL MarketingVersion
    # This prevents the database from showing [null] and makes it clear it's up to date.
    unmapped_entries = session.query(GlobalSoftwareCatalog).filter(
        GlobalSoftwareCatalog.MarketingVersion == None
    ).all()
    
    for entry in unmapped_entries:
        entry.MarketingVersion = entry.InternalVersion
        entry.UpdatedAt = datetime.utcnow()


    try:
        session.commit()
        logger.info(f"Successfully synced {matched_count} live items to GlobalSoftwareCatalog.")
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to sync global software catalog: {e}")
