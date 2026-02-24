-- Keyser Auth System (Integrated & Secure)
local BASE_URL = "http://localhost:3001" 

-- Hardware Token Identification
local function KeyserGetAuthTokenFix()
    local token = KeyserGetAuthToken()
    return token:gsub("%s+", "") -- Remove any potential whitespace
end

local UserToken = KeyserGetAuthTokenFix()

-- Local Auth Key Generator (The "bypass" logic from index.js)
local function generateAuthKey(key)
    local base = "phantom_secure_"
    local secret = "phantom_secret_key"
    local combined = key .. secret
    local hash = 0
    for i = 1, #combined do
        -- logic matches index.js: hash = (hash + charCode * ((i+1)*7)) * 31 % 10000000
        hash = (hash + combined:byte(i) * (i * 7)) * 31 % 10000000
    end
    hash = math.abs(hash) % 1000000
    return base .. tostring(hash) .. "_X7K9P2L"
end

-- 1. Verify existence in keys.txt
local KeysBin = KeyserHttpGet(BASE_URL .. "/license/keys.txt")

-- Clean BOM if present
if KeysBin:sub(1,3) == "\239\187\191" then
    KeysBin = KeysBin:sub(4)
end

if KeysBin ~= "" and not KeysBin:find("-- Access denied") then
    local found = false
    for line in KeysBin:gmatch("[^\r\n]+") do
        local keyInFile = line:match("([^|]+)")
        if keyInFile and keyInFile:gsub("%s+", "") == UserToken then
            found = true
            break
        end
    end

    if found then
        print("[phantom] Connecting...")
        local SessionAuth = generateAuthKey(UserToken)
        local mainScript = KeyserHttpGet(BASE_URL .. "/license/main.lua?auth=" .. SessionAuth .. "&key=" .. UserToken)
        
        if mainScript ~= "" and not mainScript:find("-- Access denied") then
            -- Fetch User Info (Optional logging)
            local infoRaw = KeyserHttpGet(BASE_URL .. "/license/info?key=" .. UserToken)
            if infoRaw ~= "" and infoRaw:find("|") then
                local sName, sExp = infoRaw:match("([^|]+)|(.*)")
                print("[phantom] Hello, " .. (sName or "User") .. " | Expiration: " .. (sExp or "Permanent"))
            end

            local loadFunc, err = load(mainScript)
            if loadFunc then
                print("[phantom] Successfully authenticated.")
                loadFunc()
            else
                print("[phantom] Load error: " .. tostring(err))
            end
            return
        else
            print("[phantom] Fetch failed or denied.")
        end
    else
        print("[phantom] Membership not found: " .. UserToken)
    end
else
    print("[phantom] Connection failed or server offline.")
end
