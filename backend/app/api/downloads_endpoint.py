
@router.get("/installer/exe")
async def get_installer_exe(key: str, db: AsyncSession = Depends(get_db)):
    # Serve the Generic Signed Installer but rename it so it contains the Key
    tenant_result = await db.execute(select(Tenant).where(Tenant.ApiKey == key))
    tenant = tenant_result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Invalid Key")

    # Path to signed installer (Located in Storage Volume)
    # We moved it to storage/AgentTemplate/win-x64/monitorix-installer.exe
    installer_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../storage/AgentTemplate/win-x64/monitorix-installer.exe"))
    
    if not os.path.exists(installer_path):
        print(f"[Downloads] Installer missing at: {installer_path}")
        raise HTTPException(status_code=404, detail="Installer Not Available (File Missing)")
        
    filename = f"monitorix-installer-{tenant.ApiKey}.exe"
    
    return FileResponse(installer_path, media_type="application/vnd.microsoft.portable-executable", filename=filename)
