const express = require('express');  
const User = require('../models/User');  
const jwt = require('jsonwebtoken');  
const router = express.Router();  

// Middleware d'authentification  
const protect = (req, res, next) => {  
    const token = req.headers['authorization']?.split(' ')[1];  
    if (!token) return res.status(401).json({ message: 'Pas de token, accès refusé' });  

    try {  
        const decoded = jwt.verify(token, process.env.JWT_SECRET);  
        req.user = decoded;  
        next();  
    } catch (error) {  
        return res.status(401).json({ message: 'Token non valide' });  
    }  
};  

// Endpoint d'inscriptions  
router.post('/register', async (req, res) => {  
    const { username, email, password } = req.body;  
    try {  
        const user = new User({ username, email, password });  
        await user.save();  
        res.status(201).json({ message: 'Utilisateur créé avec succès' });  
    } catch (error) {  
        res.status(400).json({ message: 'Erreur lors de la création de l’utilisateur', error });  
    }  
});  

// Endpoint de connexion  
router.post('/login', async (req, res) => {  
    const { email, password } = req.body;  
    try {  
        const user = await User.findOne({ email });  
        if (!user || !(await user.matchPassword(password))) {  
            return res.status(401).json({ message: 'Identifiants invalides' });  
        }  

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });  
        res.json({ token });  
    } catch (error) {  
        res.status(500).json({ message: 'Erreur du serveur', error });  
    }  
});  

// Endpoint pour récupérer les informations d'un utilisateur (Protected)  
router.get('/me', protect, (req, res) => {  
    res.json(req.user);  
});  

// Endpoint de mise à jour d'un utilisateur (admin seulement, Protected)  
router.put('/:id', protect, async (req, res) => {  
    if (req.user.role !== 'admin') {  
        return res.status(403).json({ message: 'Accès refusé' });  
    }  
    const { username, email, password } = req.body;  
    try {  
        const user = await User.findByIdAndUpdate(req.params.id, { username, email, password }, { new: true });  
        res.json(user);  
    } catch (error) {  
        res.status(400).json({ message: 'Erreur lors de la mise à jour de l’utilisateur', error });  
    }  
});  

// Endpoint de suppression d'un utilisateur (admin seulement)  
router.delete('/:id', protect, async (req, res) => {  
    if (req.user.role !== 'admin') {  
        return res.status(403).json({ message: 'Accès refusé' });  
    }  
    try {  
        await User.findByIdAndDelete(req.params.id);  
        res.json({ message: 'Utilisateur supprimé' });  
    } catch (error) {  
        res.status(400).json({ message: 'Erreur lors de la suppression de l’utilisateur', error });  
    }  
});  

// Récupérer tous les utilisateurs (admin seulement)  
router.get('/', protect, async (req, res) => {  
    if (req.user.role !== 'admin') {  
        return res.status(403).json({ message: 'Accès refusé' });  
    }  
    try {  
        const users = await User.find();  
        res.json(users);  
    } catch (error) {  
        res.status(500).json({ message: 'Erreur du serveur', error });  
    }  
});  

module.exports = router;