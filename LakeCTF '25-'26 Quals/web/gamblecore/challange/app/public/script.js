const audioWin = new Audio('/audio/win.mp3');
const audioLose = new Audio('/audio/aww-dang-it.mp3');
const audioEnter = new Audio('/audio/lets-go-gambling.mp3');

// Overlay for entering (to enable audio context)
const overlay = document.createElement('div');
overlay.style.position = 'fixed';
overlay.style.top = '0';
overlay.style.left = '0';
overlay.style.width = '100%';
overlay.style.height = '100%';
overlay.style.backgroundColor = 'rgba(0,0,0,0.9)';
overlay.style.display = 'flex';
overlay.style.justifyContent = 'center';
overlay.style.alignItems = 'center';
overlay.style.zIndex = '1000';
overlay.innerHTML = '<button id="enter-btn" style="font-size: 24px; padding: 20px;">Enter Casino</button>';
document.body.appendChild(overlay);

document.getElementById('enter-btn').addEventListener('click', () => {
    overlay.style.display = 'none';
    audioEnter.play().catch(e => console.log('Audio play failed', e));
    updateBalance();
});

async function updateBalance() {
    try {
        const res = await fetch('/api/balance');
        const data = await res.json();
        document.getElementById('mc-balance').innerText = `${data.microcoins} µC`;
        document.getElementById('usd-balance').innerText = `$${data.usd.toFixed(2)}`;
    } catch (e) {
        console.error(e);
    }
}

function fakeAction() {
    alert("This feature is unavailable at the moment.");
}

document.getElementById('gamble-btn').addEventListener('click', async () => {
    const amountInput = parseFloat(document.getElementById('bet-amount').value);
    const currency = document.getElementById('bet-currency').value;
    
    if (isNaN(amountInput) || amountInput <= 0) {
        alert('Invalid amount');
        return;
    }

    // If currency is coins (Microcoins in UI), convert to Coins for backend
    let amountToSend = amountInput;
    if (currency === 'coins') {
        amountToSend = amountInput / 1000000; // Convert Microcoins to Coins
    }

    try {
        const res = await fetch('/api/gamble', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currency, amount: amountToSend })
        });
        const data = await res.json();

        if (res.ok) {
            const resultEl = document.getElementById('gamble-result');
            if (data.win) {
                resultEl.innerText = `You won! +${data.winnings}`;
                resultEl.style.color = 'green';
                audioWin.currentTime = 0;
                audioWin.play();
            } else {
                resultEl.innerText = 'Aw dang it! You lost.';
                resultEl.style.color = 'red';
                audioLose.currentTime = 0;
                audioLose.play();
            }
            updateBalance();
        } else {
            alert(data.error);
        }
    } catch (e) {
        console.error(e);
    }
});

document.getElementById('convert-btn').addEventListener('click', async () => {
    const amount = document.getElementById('convert-amount').value;
    try {
        const res = await fetch('/api/convert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount: parseInt(amount) })
        });
        const data = await res.json();
        if (res.ok) {
            document.getElementById('convert-msg').innerText = data.message;
            document.getElementById('convert-msg').style.color = 'green';
            updateBalance();
        } else {
            document.getElementById('convert-msg').innerText = data.error;
            document.getElementById('convert-msg').style.color = 'red';
        }
    } catch (e) {
        console.error(e);
    }
});

document.getElementById('buy-flag-btn').addEventListener('click', async () => {
    try {
        const res = await fetch('/api/flag', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            document.getElementById('flag-display').innerText = data.flag;
            document.getElementById('flag-display').style.color = 'gold';
            document.getElementById('flag-display').style.fontSize = '24px';
        } else {
            alert(data.error);
        }
    } catch (e) {
        console.error(e);
    }
});

// Initial load (if no overlay)
// updateBalance();

