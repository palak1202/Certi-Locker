// eslint-disable-next-line no-undef
const CrediManager = artifacts.require("CrediManager");

export default async function (deployer) {
    await deployer.deploy(
        CrediManager,
        "0x2d448079B91C1BeB7b80281D367435321cA19Bb2",
        "Palak",
        "Bende",
        "palakbende",
        "palakbende12@gmail.com",
        "Admin"
    );
};
