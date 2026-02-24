const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder } = require('discord.js');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';

// CORS ayarları
app.use(cors());
app.use(express.json());

// Trust proxy - IP adresini doğru almak için
app.set('trust proxy', true);

// Keys dosyası yolu
const KEYS_FILE_PATH = path.join(__dirname, 'keys', 'keys.txt');
const MAIN_LUA_PATH = path.join(__dirname, 'scripts', 'main.lua');
const BACKUPS_DIR = path.join(__dirname, 'backups');

// Backups klasörü yoksa oluştur
if (!fs.existsSync(BACKUPS_DIR)) {
    fs.mkdirSync(BACKUPS_DIR);
}

// Discord Webhook URL'leri
const WEBHOOK_LUA_UPDATE = process.env.WEBHOOK_LUA_UPDATE || '';
const WEBHOOK_KEY_ADD = process.env.WEBHOOK_KEY_ADD || '';
const WEBHOOK_KEY_DELETE = process.env.WEBHOOK_KEY_DELETE || '';
const WEBHOOK_LUA_OPEN = process.env.WEBHOOK_LUA_OPEN || '';

// /license/keys.txt endpoint'i - Crack koruması ile
app.get('/license/keys.txt', (req, res) => {
    try {
        const userAgent = req.get('User-Agent') || '';
        if (isBrowserRequest(userAgent)) {
            res.status(404).setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send('-- Access denied');
            return;
        }

        if (fs.existsSync(KEYS_FILE_PATH)) {
            const keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
            res.setHeader('Content-Type', 'text/plain');
            res.send(keysContent);
        } else {
            res.setHeader('Content-Type', 'text/plain');
            res.send('');
        }
    } catch (error) {
        console.error('Error reading keys file:', error);
        res.setHeader('Content-Type', 'text/plain');
        res.send('');
    }
});

// Key'den isim alma fonksiyonu (endpoint için)
function getNameByKeyFromFile(key) {
    try {
        if (!fs.existsSync(KEYS_FILE_PATH)) {
            return null;
        }

        let keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
        if (keysContent.charCodeAt(0) === 0xFEFF) {
            keysContent = keysContent.slice(1);
        }
        const lines = keysContent.split('\n').filter(l => l.trim() !== '');

        for (let line of lines) {
            const parts = line.split('|');
            const lineKey = parts[0];
            if (lineKey && lineKey.trim() === key.trim()) {
                return parts[1] ? parts[1].trim() : null;
            }
        }

        return null;
    } catch (error) {
        console.error('Key\'den isim alma hatası:', error);
        return null;
    }
}

// Webhook gönderme fonksiyonu
async function sendWebhook(webhookUrl, embedData, files = []) {
    try {
        if (!webhookUrl) return;

        const formData = {
            embeds: [embedData]
        };

        if (files.length > 0) {
            const FormData = require('form-data');
            const form = new FormData();
            form.append('payload_json', JSON.stringify(formData));

            files.forEach((file, index) => {
                form.append(`file${index}`, file.buffer, file.filename);
            });

            await axios.post(webhookUrl, form, {
                headers: form.getHeaders()
            });
        } else {
            await axios.post(webhookUrl, formData);
        }
    } catch (error) {
        console.error('Webhook gönderme hatası:', error.message);
    }
}

// User-Agent kontrolü fonksiyonu
function isBrowserRequest(userAgent) {
    if (!userAgent || userAgent === '') return false;

    const browserPatterns = [
        'Mozilla', 'Chrome', 'Firefox', 'Safari', 'Edge', 'Opera',
        'Gecko', 'WebKit', 'Trident', 'MSIE', 'Internet Explorer',
        'curl', 'wget', 'Postman', 'Insomnia', 'HTTPie',
        'Python', 'Java', 'Go-http-client', 'node-fetch', 'axios',
        'libwww-perl', 'WWW-Mechanize', 'Apache-HttpClient'
    ];

    const ua = userAgent.toLowerCase();
    for (const pattern of browserPatterns) {
        if (ua.includes(pattern.toLowerCase())) {
            return true;
        }
    }

    return false;
}

// Crack koruması - Dinamik şifre oluşturma
function generateAuthKey(key) {
    if (!key) return null;
    const base = "phantom_secure_";
    let hash = 0;
    const serverSecret = "phantom_secret_key";

    const combined = key + serverSecret;
    for (let i = 0; i < combined.length; i++) {
        hash += combined.charCodeAt(i) * ((i + 1) * 7);
        hash = (hash * 31) % 10000000;
    }
    hash = Math.abs(hash) % 1000000;
    return base + hash.toString() + "_X7K9P2L";
}

// /license/auth endpoint'i
app.get('/license/auth', (req, res) => {
    try {
        const userAgent = req.get('User-Agent') || '';
        console.log('[AUTH] User-Agent:', userAgent);
        console.log('[AUTH] Key:', req.query.key);

        if (isBrowserRequest(userAgent)) {
            console.log('[AUTH] Browser detected, access denied');
            res.status(404).setHeader('Content-Type', 'text/plain');
            res.send('-- Access denied');
            return;
        }

        const key = req.query.key;

        if (!key) {
            res.status(400).setHeader('Content-Type', 'text/plain');
            res.send('-- Invalid key parameter');
            return;
        }

        if (!fs.existsSync(KEYS_FILE_PATH)) {
            res.status(404).setHeader('Content-Type', 'text/plain');
            res.send('-- Keys file not found');
            return;
        }

        let keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
        if (keysContent.charCodeAt(0) === 0xFEFF) {
            keysContent = keysContent.slice(1);
        }
        const lines = keysContent.split('\n').filter(l => l.trim() !== '');

        let keyFound = false;
        for (let line of lines) {
            const [lineKey] = line.split('|');
            if (lineKey && lineKey.trim() === key.trim()) {
                keyFound = true;
                break;
            }
        }

        if (!keyFound) {
            res.status(404).setHeader('Content-Type', 'text/plain');
            res.send('-- Key not found');
            return;
        }

        const authKey = generateAuthKey(key);
        console.log('[AUTH] Key found, generating auth key:', authKey);
        res.setHeader('Content-Type', 'text/plain');
        res.send(authKey);
    } catch (error) {
        console.error('Error generating auth key:', error);
        res.status(500).setHeader('Content-Type', 'text/plain');
        res.send('-- Server error');
    }
});

// /license/info endpoint'i - Loader için kullanıcı bilgilerini döner
app.get('/license/info', (req, res) => {
    try {
        const userAgent = req.get('User-Agent') || '';
        if (isBrowserRequest(userAgent)) {
            res.status(404).setHeader('Content-Type', 'text/plain');
            res.send('-- Access denied');
            return;
        }

        const key = req.query.key;
        console.log('[INFO] Info requested for key:', key);
        if (!key) {
            res.status(400).send('-- Missing key');
            return;
        }

        if (!fs.existsSync(KEYS_FILE_PATH)) {
            res.status(404).send('-- Keys file not found');
            return;
        }

        let keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
        if (keysContent.charCodeAt(0) === 0xFEFF) {
            keysContent = keysContent.slice(1);
        }
        const lines = keysContent.split('\n').filter(l => l.trim() !== '');

        for (let line of lines) {
            const parts = line.split('|');
            if (parts[0] && parts[0].trim() === key.trim()) {
                const name = parts[1] || 'User';
                const yil = parseInt(parts[2]) || 0;
                const ay = parseInt(parts[3]) || 0;
                const gun = parseInt(parts[4]) || 0;

                let expiryStr = `${gun}/${ay}/${yil}`;
                if (yil >= 2090) expiryStr = "Lifetime";

                console.log(`[INFO] Returning info for ${name}: ${expiryStr}`);
                res.setHeader('Content-Type', 'text/plain');
                res.send(`${name}|${expiryStr}`);
                return;
            }
        }
        console.log('[INFO] Key not found in database:', key);

        res.status(404).send('-- Key not found');
    } catch (error) {
        console.error('Info error:', error);
        res.status(500).send('-- Server error');
    }
});

// /license/main.lua endpoint'i
app.get('/license/main.lua', (req, res) => {
    try {
        const authKey = req.query.auth;
        const key = req.query.key;

        const expectedAuthKey = key ? generateAuthKey(key) : null;

        const userAgent = req.get('User-Agent') || '';
        if (isBrowserRequest(userAgent)) {
            res.status(404).setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send('-- Access denied');
            return;
        }

        if (!authKey || !expectedAuthKey || authKey !== expectedAuthKey) {
            const crackMessage = '-- Crack koruması tetiklendi!\n' +
                'print("heee cracklıyon dimi")\n' +
                'MachoMenuNotification("[phantom.lua]", "heee cracklıyon dimi")\n' +
                'return';
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(crackMessage);
            return;
        }

        if (fs.existsSync(MAIN_LUA_PATH)) {
            let luaContent = fs.readFileSync(MAIN_LUA_PATH, 'utf8');
            if (luaContent.charCodeAt(0) === 0xFEFF) {
                luaContent = luaContent.slice(1);
            }

            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(luaContent);

            const clientIp = req.ip ||
                (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : null) ||
                req.connection.remoteAddress ||
                req.socket.remoteAddress ||
                'Bilinmiyor';
            const serverIp = HOST === '0.0.0.0' ? 'localhost' : HOST;
            const keyName = getNameByKeyFromFile(key) || 'DEVELOPER';

            const luaOpenEmbed = {
                title: '🎮 Lua Açılış Logu',
                color: 0x00FF00,
                fields: [
                    { name: '🔑 Key', value: `\`${key}\``, inline: true },
                    { name: '👤 İsim', value: keyName, inline: true },
                    { name: '🌐 Client IP', value: clientIp, inline: true },
                    { name: '🖥️ Sunucu IP', value: `${serverIp}:${PORT}`, inline: true },
                    { name: '⏰ Zaman', value: new Date().toLocaleString('tr-TR'), inline: true }
                ],
                timestamp: new Date().toISOString()
            };

            sendWebhook(WEBHOOK_LUA_OPEN, luaOpenEmbed);
        } else {
            res.status(404).setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send('-- Main Lua file not found');
        }
    } catch (error) {
        console.error('Error reading main.lua file:', error);
        res.status(500).setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.send('-- Internal server error');
    }
});

// Ana sayfa
app.get('/', (req, res) => {
    res.send('MachoKey Authentication Server - Running on port ' + PORT);
});

// ============================================
// DISCORD BOT
// ============================================

console.log('🔍 .env dosyası kontrol ediliyor...');
console.log('DISCORD_BOT_TOKEN:', process.env.DISCORD_BOT_TOKEN ? '✅ Bulundu' : '❌ Bulunamadı');
console.log('DISCORD_CLIENT_ID:', process.env.DISCORD_CLIENT_ID ? '✅ Bulundu' : '❌ Bulunamadı');
console.log('DISCORD_GUILD_ID:', process.env.DISCORD_GUILD_ID ? `✅ Bulundu: ${process.env.DISCORD_GUILD_ID}` : '⚠️ Belirtilmemiş (tüm sunucularda çalışır)');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ]
});

const commands = [
    new SlashCommandBuilder()
        .setName('key-ekle')
        .setDescription('Key ekler')
        .addStringOption(option =>
            option.setName('key').setDescription('Eklenecek key').setRequired(true))
        .addStringOption(option =>
            option.setName('isim').setDescription('Key sahibinin ismi').setRequired(true))
        .addIntegerOption(option =>
            option.setName('yil').setDescription('Yıl sayısı').setRequired(true))
        .addIntegerOption(option =>
            option.setName('gun').setDescription('Gün sayısı').setRequired(true))
        .addIntegerOption(option =>
            option.setName('saat').setDescription('Saat sayısı').setRequired(true)),
    new SlashCommandBuilder()
        .setName('key-sil')
        .setDescription('Key siler')
        .addStringOption(option =>
            option.setName('key').setDescription('Silinecek key').setRequired(true)),
    new SlashCommandBuilder()
        .setName('update')
        .setDescription('Update atar')
        .addAttachmentOption(option =>
            option.setName('file').setDescription('Yeni main.lua dosyası').setRequired(true)),
    new SlashCommandBuilder()
        .setName('rollback')
        .setDescription('Bir önceki yedeğe geri döner'),
    new SlashCommandBuilder()
        .setName('key-list')
        .setDescription('Key listesini gösterir (Özel)')
].map(command => command.toJSON());

if (process.env.DISCORD_BOT_TOKEN && process.env.DISCORD_CLIENT_ID) {
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_BOT_TOKEN);

    async function registerCommands() {
        try {
            console.log('🔄 Discord bot komutları kaydediliyor...');
            await rest.put(
                Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
                { body: commands }
            );
            console.log('✅ Komutlar başarıyla kaydedildi!');
        } catch (error) {
            console.error('❌ Komut kaydetme hatası:', error.message);
            if (error.code === 50001) {
                console.error('Bot token geçersiz veya bot Discord Developer Portal\'da doğru ayarlanmamış!');
            }
        }
    }

    registerCommands();

    function addKey(key, isim, yil, gun, saat) {
        try {
            if (!fs.existsSync(KEYS_FILE_PATH)) {
                fs.writeFileSync(KEYS_FILE_PATH, '', 'utf8');
            }

            let keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
            const lines = keysContent.split('\n').filter(l => l.trim() !== '');

            for (let line of lines) {
                const [existingKey] = line.split('|');
                if (existingKey && existingKey.trim() === key.trim()) {
                    return { success: false, message: 'Bu key zaten mevcut!' };
                }
            }

            lines.push(`${key}|${isim}|${yil}|${gun}|${saat}`);
            fs.writeFileSync(KEYS_FILE_PATH, lines.join('\n') + '\n', 'utf8');

            return { success: true, message: `Key başarıyla eklendi: ${key} (İsim: ${isim}, Yıl: ${yil}, Gün: ${gun}, Saat: ${saat})` };
        } catch (error) {
            return { success: false, message: `Hata: ${error.message}` };
        }
    }

    function deleteKey(key) {
        try {
            if (!fs.existsSync(KEYS_FILE_PATH)) {
                return { success: false, message: 'Keys.txt dosyası bulunamadı!' };
            }

            let keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
            const lines = keysContent.split('\n').filter(l => l.trim() !== '');
            const originalLength = lines.length;

            const filteredLines = lines.filter(line => {
                const [lineKey] = line.split('|');
                return lineKey && lineKey.trim() !== key.trim();
            });

            if (filteredLines.length === originalLength) {
                return { success: false, message: 'Bu key bulunamadı!' };
            }

            fs.writeFileSync(KEYS_FILE_PATH, filteredLines.join('\n') + (filteredLines.length > 0 ? '\n' : ''), 'utf8');

            return { success: true, message: `Key başarıyla silindi: ${key}` };
        } catch (error) {
            return { success: false, message: `Hata: ${error.message}` };
        }
    }

    function getNameByKey(key) {
        return getNameByKeyFromFile(key);
    }

    async function updateMainLua(attachment) {
        try {
            let previousContent = null;
            if (fs.existsSync(MAIN_LUA_PATH)) {
                // Yedekle
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const backupPath = path.join(BACKUPS_DIR, `main-backup-${timestamp}.lua`);
                previousContent = fs.readFileSync(MAIN_LUA_PATH, 'utf8');
                fs.writeFileSync(backupPath, previousContent, 'utf8');
                console.log(`[BACKUP] Saved: ${backupPath}`);

                fs.unlinkSync(MAIN_LUA_PATH);
            }

            const response = await axios.get(attachment.url, {
                responseType: 'text',
                encoding: 'utf8'
            });

            fs.writeFileSync(MAIN_LUA_PATH, response.data, 'utf8');

            return { success: true, message: 'main.lua başarıyla güncellendi ve yedeklendi!', oldData: previousContent };
        } catch (error) {
            return { success: false, message: `Hata: ${error.message}` };
        }
    }

    async function rollbackMainLua() {
        try {
            if (!fs.existsSync(BACKUPS_DIR)) return { success: false, message: 'Backups klasörü bulunamadı!' };

            const files = fs.readdirSync(BACKUPS_DIR)
                .filter(f => f.startsWith('main-backup-'))
                .sort((a, b) => {
                    return fs.statSync(path.join(BACKUPS_DIR, b)).mtime.getTime() -
                        fs.statSync(path.join(BACKUPS_DIR, a)).mtime.getTime();
                });

            if (files.length === 0) return { success: false, message: 'Geri dönecek yedek bulunamadı!' };

            const latestBackup = files[0];
            const backupPath = path.join(BACKUPS_DIR, latestBackup);
            const content = fs.readFileSync(backupPath, 'utf8');

            fs.writeFileSync(MAIN_LUA_PATH, content, 'utf8');

            // Kullanılan yedeği sil (opsiyonel) veya taşı
            // fs.unlinkSync(backupPath); 

            return { success: true, message: `En son yedeğe (${latestBackup}) başarıyla geri dönüldü!` };
        } catch (error) {
            return { success: false, message: `Rollback hatası: ${error.message}` };
        }
    }

    client.on('ready', () => {
        console.log(`✅ Discord botu hazır! ${client.user.tag} olarak giriş yapıldı.`);
        console.log(`Bot ID: ${client.user.id}`);
        console.log(`Sunucu sayısı: ${client.guilds.cache.size}`);
        registerCommands();
    });

    client.on('error', error => {
        console.error('❌ Bot hatası:', error);
    });

    client.on('disconnect', () => {
        console.log('⚠️ Bot bağlantısı kesildi!');
    });

    client.on('reconnecting', () => {
        console.log('🔄 Bot yeniden bağlanıyor...');
        registerCommands();
    });

    setInterval(() => {
        if (client.isReady()) {
            console.log('🔄 Periyodik komut güncelleme kontrolü...');
            registerCommands();
        }
    }, 60 * 1000);

    function isSpecialUser(interaction) {
        const specialUserIds = ['1384947437281738815', '693648181967454355'];
        return specialUserIds.includes(interaction.user.id);
    }

    function hasPermission(member, interaction) {
        if (isSpecialUser(interaction)) return true;
        if (interaction.guild && interaction.guild.ownerId === interaction.user.id) return true;
        if (member.permissions.has('Administrator')) return true;
        if (process.env.DISCORD_ALLOWED_ROLE_ID && member.roles.cache.has(process.env.DISCORD_ALLOWED_ROLE_ID)) return true;
        if (process.env.DISCORD_ALLOWED_ROLE_NAME) {
            const allowedRoleName = process.env.DISCORD_ALLOWED_ROLE_NAME.toLowerCase();
            if (member.roles.cache.some(role => role.name.toLowerCase() === allowedRoleName)) return true;
        }
        return false;
    }

    client.on('interactionCreate', async interaction => {
        if (!interaction.isChatInputCommand()) return;

        const { commandName, member, guild } = interaction;

        if (process.env.DISCORD_GUILD_ID) {
            if (guild && guild.id !== process.env.DISCORD_GUILD_ID) {
                await interaction.reply({
                    content: '❌ Bu komut bu sunucuda kullanılamaz!',
                    ephemeral: true
                });
                return;
            }
        }

        if (!hasPermission(member, interaction)) {
            await interaction.reply({
                content: '❌ Bu komutu kullanmak için yetkiniz yok! (Sunucu sahibi, yönetici veya yetkili rol gerekli)',
                ephemeral: true
            });
            return;
        }

        if (commandName === 'key-ekle') {
            const key = interaction.options.getString('key');
            const isim = interaction.options.getString('isim');
            const yil = interaction.options.getInteger('yil');
            const gun = interaction.options.getInteger('gun');
            const saat = interaction.options.getInteger('saat');
            const result = addKey(key, isim, yil, gun, saat);

            await interaction.reply({
                content: result.message,
                ephemeral: true
            });

            if (result.success) {
                const keyAddEmbed = {
                    title: '🟢 Yeni Lisans Anahtarı Oluşturuldu',
                    description: 'Sisteme yeni bir lisans anahtarı başarıyla tanımlandı.',
                    color: 0x2ECC71, // Emerald Green
                    thumbnail: { url: 'https://i.imgur.com/8N9SOnF.png' }, // Opsiyonel anahtar ikonu
                    fields: [
                        { name: '🔑 Lisans Anahtarı', value: `\`${key}\``, inline: false },
                        { name: '👤 Kullanıcı İsmi', value: `\`${isim}\``, inline: true },
                        { name: '⏳ Geçerlilik Süresi', value: `\`${yil} Yıl, ${gun} Gün, ${saat} Saat\``, inline: true },
                        { name: '🛠️ Ekleyen Yetkili', value: `<@${interaction.user.id}> (\`${interaction.user.tag}\`)`, inline: false },
                        { name: '⏰ Oluşturulma Tarihi', value: `\`${new Date().toLocaleString('tr-TR')}\``, inline: true }
                    ],
                    footer: { text: 'Keyser Auth System • Veritabanı Güncellendi' },
                    timestamp: new Date().toISOString()
                };
                sendWebhook(WEBHOOK_KEY_ADD, keyAddEmbed);
            }
        }

        if (commandName === 'key-sil') {
            const key = interaction.options.getString('key');
            const deletedKeyName = getNameByKey(key) || 'Bilinmiyor';
            const result = deleteKey(key);

            await interaction.reply({
                content: result.message,
                ephemeral: true
            });

            if (result.success) {
                const keyDeleteEmbed = {
                    title: '🔴 Lisans Anahtarı İptal Edildi',
                    description: 'Belirtilen lisans anahtarı sistemden tamamen kaldırıldı.',
                    color: 0xE74C3C, // Alizarin Red
                    thumbnail: { url: 'https://i.imgur.com/pYv6E6A.png' }, // Opsiyonel silme ikonu
                    fields: [
                        { name: '🔑 İptal Edilen Key', value: `\`${key}\``, inline: false },
                        { name: '👤 Sahibi', value: `\`${deletedKeyName}\``, inline: true },
                        { name: '🗑️ Silen Yetkili', value: `<@${interaction.user.id}> (\`${interaction.user.tag}\`)`, inline: false },
                        { name: '⏰ İşlem Tarihi', value: `\`${new Date().toLocaleString('tr-TR')}\``, inline: true }
                    ],
                    footer: { text: 'Keyser Auth System • Veritabanı Temizlendi' },
                    timestamp: new Date().toISOString()
                };
                sendWebhook(WEBHOOK_KEY_DELETE, keyDeleteEmbed);
            }
        }

        if (commandName === 'update') {
            const attachment = interaction.options.getAttachment('file');

            if (!attachment.name.endsWith('.lua')) {
                await interaction.reply({
                    content: 'Lütfen .lua uzantılı bir dosya yükleyin!',
                    ephemeral: true
                });
                return;
            }

            await interaction.deferReply({ ephemeral: true });

            const result = await updateMainLua(attachment);

            await interaction.editReply({
                content: result.message
            });

            if (result.success) {
                const fs = require('fs');
                const path = require('path');
                const fileBuffer = fs.readFileSync(MAIN_LUA_PATH);

                // Get first key from keys.txt for the download link
                let firstKey = 'YOUR_KEY_HERE';
                try {
                    const keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
                    const lines = keysContent.split('\n').filter(l => l.trim() !== '');
                    if (lines.length > 0) {
                        firstKey = lines[0].split('|')[0].trim();
                    }
                } catch (e) { }

                const serverIp = (process.env.HOST && process.env.HOST !== '0.0.0.0') ? process.env.HOST : 'localhost';
                const authKey = generateAuthKey(firstKey);
                const downloadLink = `http://${serverIp}:${PORT}/license/main.lua?auth=${authKey}&key=${firstKey}`;

                const luaUpdateEmbed = {
                    title: '🚀 Lua Modülü Başarıyla Güncellendi',
                    description: 'Sunucu üzerindeki ana modül dosyası güncellendi ve eski sürümü yedeklendi.',
                    color: 0x00FF7F, // SpringGreen
                    fields: [
                        { name: '📄 Dosya Adı', value: `\`${attachment.name}\``, inline: true },
                        { name: '📦 Dosya Boyutu', value: `\`${(attachment.size / 1024).toFixed(2)} KB\``, inline: true },
                        { name: '📁 Klasör', value: '`scripts/main.lua`', inline: true },
                        { name: '👤 Güncelleyen', value: `<@${interaction.user.id}> (\`${interaction.user.tag}\`)`, inline: false },
                        { name: '⏰ Zaman', value: `\`${new Date().toLocaleString('tr-TR')}\``, inline: true },
                        { name: '🔗 İndirme Bağlantısı', value: `[Tıkla ve İndir](${downloadLink})`, inline: false }
                    ],
                    footer: { text: 'Keyser Auth System • Güvenli Yükleme Tamamlandı' },
                    timestamp: new Date().toISOString()
                };

                const filesToSend = [
                    { buffer: fileBuffer, filename: attachment.name }
                ];

                if (result.oldData) {
                    filesToSend.push({
                        buffer: Buffer.from(result.oldData, 'utf8'),
                        filename: 'previous-version-backup.lua'
                    });
                }

                sendWebhook(WEBHOOK_LUA_UPDATE, luaUpdateEmbed, filesToSend);
            }
        }

        if (commandName === 'rollback') {
            await interaction.deferReply({ ephemeral: true });
            const result = await rollbackMainLua();
            await interaction.editReply({ content: result.message });
        }

        if (commandName === 'key-list') {
            if (!isSpecialUser(interaction)) {
                await interaction.reply({
                    content: '❌ Bu komutu kullanmak için özel yetkiniz yok!',
                    ephemeral: true
                });
                return;
            }

            function getKeyList() {
                try {
                    if (!fs.existsSync(KEYS_FILE_PATH)) return [];

                    let keysContent = fs.readFileSync(KEYS_FILE_PATH, 'utf8');
                    const lines = keysContent.split('\n').filter(l => l.trim() !== '');
                    const keyList = [];

                    for (let line of lines) {
                        const [key, isim] = line.split('|');
                        if (key && key.trim()) {
                            keyList.push({
                                key: key.trim(),
                                isim: isim ? isim.trim() : 'DEVELOPER'
                            });
                        }
                    }
                    return keyList;
                } catch (error) {
                    console.error('Key listesi alma hatası:', error);
                    return [];
                }
            }

            const keyList = getKeyList();
            const { EmbedBuilder } = require('discord.js');

            if (keyList.length === 0) {
                const embed = new EmbedBuilder()
                    .setTitle('📋 Key Listesi')
                    .setDescription('Henüz hiç key eklenmemiş.')
                    .setColor(0xFF0000)
                    .setTimestamp();
                await interaction.reply({ embeds: [embed], ephemeral: true });
                return;
            }

            const embed = new EmbedBuilder()
                .setTitle('📋 Key Listesi')
                .setColor(0x00FF00)
                .setTimestamp()
                .setFooter({ text: `Toplam ${keyList.length} key` });

            const fields = keyList.map((item, index) => ({
                name: `Key #${index + 1}`,
                value: `**Key:** \`${item.key}\`\n**İsim:** ${item.isim}`,
                inline: false
            }));

            if (fields.length <= 25) {
                embed.addFields(fields);
                await interaction.reply({ embeds: [embed], ephemeral: true });
            } else {
                const chunks = [];
                for (let i = 0; i < fields.length; i += 25) {
                    chunks.push(fields.slice(i, i + 25));
                }

                const firstEmbed = new EmbedBuilder()
                    .setTitle('📋 Key Listesi (1/' + chunks.length + ')')
                    .setColor(0x00FF00)
                    .setTimestamp()
                    .setFooter({ text: `Toplam ${keyList.length} key` })
                    .addFields(chunks[0]);

                await interaction.reply({ embeds: [firstEmbed], ephemeral: true });

                for (let i = 1; i < chunks.length; i++) {
                    const followUpEmbed = new EmbedBuilder()
                        .setTitle('📋 Key Listesi (' + (i + 1) + '/' + chunks.length + ')')
                        .setColor(0x00FF00)
                        .setTimestamp()
                        .addFields(chunks[i]);

                    await interaction.followUp({
                        embeds: [followUpEmbed],
                        ephemeral: true
                    });
                }
            }
        }
    });

    console.log('Bot başlatılıyor...');
    client.login(process.env.DISCORD_BOT_TOKEN).catch(error => {
        console.error('❌ Bot giriş hatası:', error.message);
        if (error.message.includes('TOKEN_INVALID')) {
            console.error('Bot token geçersiz! Lütfen .env dosyasındaki DISCORD_BOT_TOKEN değerini kontrol edin.');
        }
    });
} else {
    console.log('⚠️ Discord bot token veya client ID bulunamadı. Bot başlatılmıyor.');
}

// ============================================
// SERVER BAŞLATMA
// ============================================

app.listen(PORT, HOST, () => {
    console.log(`✅ Server running on http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    console.log(`Keys endpoint: http://localhost:${PORT}/license/keys.txt`);
    console.log(`Main Lua endpoint: http://localhost:${PORT}/license/main.lua`);
});
