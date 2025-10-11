// server.js
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { initialProducts } from './seeds.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// --- Configuration ---
const FRONTEND_DOMAINS = [
  "https://nexverra.in", "https://localhost:3000",
  "https://nexverra-website-1-t740.onrender.com"
];

// --- Middleware ---
app.use(cors({
  origin: FRONTEND_DOMAINS,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));



// --- MongoDB Connection ---
const MONGO_URI = process.env.MONGO_URI  || 'mongodb://127.0.0.1:27017/nexverra-website' || 'mongodb+srv://nexverra_db_user:8HnzQCgFqlPuzq50@cluster.jesf1md.mongodb.net/?retryWrites=true&w=majority&appName=Cluster' || 'mongodb://127.0.0.1:27017/nexverra-website';


const JWT_SECRET = process.env.JWT_SECRET || 'your-default-jwt-secret';

// --- Mongoose Schemas and Models ---
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  images: [{ type: String, required: true }],
  price: { type: Number, required: true },
  category: { type: String, required: true },
  downloadableFile: {
    fileName: String,
    fileData: String, // Base64 encoded ZIP
  },
});
const Product = mongoose.model('Product', productSchema);

const offerSchema = new mongoose.Schema({
  name: { type: String, unique: true, default: 'main-offer' },
  isActive: { type: Boolean, default: false },
  endTime: { type: Date, default: null },
});
const Offer = mongoose.model('Offer', offerSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    fullName: { type: String },
    contact: { type: String },
    role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
    wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    hasTemporaryPassword: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const timelineEventSchema = new mongoose.Schema({
    status: { type: String, required: true },
    description: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    planTitle: { type: String, required: true },
    planPrice: { type: Number, required: true },
    details: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['Failed', 'Pending', 'Pending Payment', 'Processing', 'Delivered', 'Refund Accepted', 'Refunded', 'Cancelled'], 
        default: 'Pending' 
    },
    downloadableFile: {
        fileName: String,
        fileData: String, // Base64 encoded ZIP
    },
    timeline: [timelineEventSchema]
}, { timestamps: true });
const Order = mongoose.model('Order', orderSchema);


// --- Data Transformation ---
const transformProduct = (productDoc) => {
  const productObj = productDoc.toObject();
  productObj.id = productObj._id.toString();
  if (productObj.downloadableFile && productObj.downloadableFile.fileName) {
      productObj.downloadableFileName = productObj.downloadableFile.fileName;
  }
  delete productObj.downloadableFile; // Always remove the large file data from general queries
  delete productObj._id;
  delete productObj.__v;
  return productObj;
};

const transformUser = (userDoc) => {
    const userObj = userDoc.toObject();
    userObj.id = userObj._id.toString();
    delete userObj._id;
    delete userObj.__v;
    delete userObj.password;
    return userObj;
};

const transformOrder = (orderDoc) => {
    const orderObj = orderDoc.toObject();
    orderObj.id = orderObj._id.toString();
    if (orderObj.user && typeof orderObj.user === 'object' && !Array.isArray(orderObj.user)) {
      delete orderObj.user._id;
      delete orderObj.user.__v;
      delete orderObj.user.password;
    }
     if (orderObj.downloadableFile && orderObj.downloadableFile.fileName) {
        orderObj.downloadableFileName = orderObj.downloadableFile.fileName;
    }
    delete orderObj.downloadableFile; // Don't send the large file data with every order fetch
    delete orderObj._id;
    delete orderObj.__v;
    return orderObj;
};


// --- Helper Functions ---
const generateOrderId = async () => {
    while (true) {
        const potentialId = `ORD-${Date.now().toString().slice(-6)}${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
        const existingOrder = await Order.findOne({ orderId: potentialId });
        if (!existingOrder) {
            return potentialId;
        }
    }
};

const constructUserPayload = (user) => {
    return {
        id: user._id.toString(),
        email: user.email,
        fullName: user.fullName,
        contact: user.contact,
        role: user.role,
        hasTemporaryPassword: !!user.hasTemporaryPassword,
        isActive: user.isActive,
        createdAt: user.createdAt.toISOString(),
    };
};

// --- Initial Data Seeding ---
const seedDatabase = async () => {
  try {
    const count = await Product.countDocuments();
    if (count === 0) {
      console.log('No products found, seeding database...');
      await Product.insertMany(initialProducts);
      console.log('✅ Database seeded successfully.');
    }
  } catch (error) {
    console.error('❌ Error seeding database:', error.message);
  }
};

const seedDemoAdminUser = async () => {
    try {
        const adminEmail = 'admin-demo@nexverra.com';
        const adminPassword = 'password';
        const hashedPassword = await bcrypt.hash(adminPassword, 12);

        const adminUser = await User.findOne({ email: adminEmail });

        if (adminUser) {
            // If admin exists, ensure password and state are correct
            adminUser.password = hashedPassword;
            adminUser.role = 'admin';
            adminUser.isActive = true;
            adminUser.hasTemporaryPassword = false;
            adminUser.username = adminEmail;
            adminUser.fullName = 'Demo Admin';
            await adminUser.save();
        } else {
            // If admin does not exist, create it
            await User.create({
                email: adminEmail,
                username: adminEmail,
                password: hashedPassword,
                fullName: 'Demo Admin',
                role: 'admin',
                isActive: true,
                hasTemporaryPassword: false,
            });
        }
        console.log(`✅ Demo admin user configured. Credentials: email=${adminEmail}, password=${adminPassword}`);
    } catch (error) {
        console.error('❌ Error configuring demo admin user:', error.message);
    }
};

const seedDemoUser = async () => {
    try {
        const demoEmail = 'user@nexverra.com';
        const demoPassword = 'password';
        const hashedPassword = await bcrypt.hash(demoPassword, 12);

        const demoUser = await User.findOne({ email: demoEmail });

        if (demoUser) {
            // If user exists, ensure password and state are correct
            demoUser.password = hashedPassword;
            demoUser.isActive = true;
            demoUser.hasTemporaryPassword = false;
            demoUser.username = demoEmail; // Ensure username is set
            await demoUser.save();
        } else {
            // If user does not exist, create it
            await User.create({
                email: demoEmail,
                username: demoEmail,
                password: hashedPassword,
                fullName: 'Demo User',
                role: 'customer',
                isActive: true,
                hasTemporaryPassword: false,
            });
        }
        console.log(`✅ Demo user configured. Credentials: email=${demoEmail}, password=${demoPassword}`);
    } catch (error) {
        console.error('❌ Error configuring demo user:', error.message);
    }
};

const initializeOffer = async () => {
  try {
    const count = await Offer.countDocuments();
    if (count === 0) {
      await new Offer().save();
      console.log('✅ Main offer document initialized.');
    }
  } catch (error) {
    console.error('❌ Error initializing offer:', error.message);
  }
};

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const authenticateAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden: Admin access required.' });
    }
    next();
};

const addUserToRequest = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return next();

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (!err) {
            req.user = user;
        }
        next();
    });
};

// --- API Routes ---

// Auth
app.post('/api/auth/register', async (req, res) => {
    const { email, password, fullName, contact, role } = req.body;
    if (!email || !password || !fullName || !contact || !role) {
        return res.status(400).json({ message: 'Please provide full name, email, contact, password, and role.' });
    }
    if (!['customer', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role specified. Must be "customer" or "admin".' });
    }
    try {
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ 
            email, 
            username: email.toLowerCase(),
            password: hashedPassword, 
            fullName, 
            contact,
            role
        });
        await newUser.save();

        const userPayload = constructUserPayload(newUser);
        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({ token, user: userPayload });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration', error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        if (!user.isActive) {
            return res.status(403).json({ message: 'Your account has been deactivated.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const userPayload = constructUserPayload(user);
        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: userPayload });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(constructUserPayload(user));
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.put('/api/auth/me/password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || !currentPassword) {
        return res.status(400).json({ message: 'Please provide both current and new passwords.' });
    }
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Incorrect current password.' });
        
        user.password = await bcrypt.hash(newPassword, 12);
        if (user.hasTemporaryPassword) {
            user.hasTemporaryPassword = false;
        }
        await user.save();
        res.json({ message: 'Password updated successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Products
app.get('/api/products', addUserToRequest, async (req, res) => {
  try {
    const products = await Product.find({}).sort({ _id: -1 });
    let productDocs = products.map(p => transformProduct(p));
    
    if (req.user) {
        const userWithWishlist = await User.findById(req.user.id).select('wishlist');
        const wishlistSet = new Set(userWithWishlist?.wishlist.map(id => id.toString()) || []);
        productDocs = productDocs.map(p => ({
            ...p,
            wishlisted: wishlistSet.has(p.id)
        }));
    } else {
        productDocs = productDocs.map(p => ({ ...p, wishlisted: false }));
    }
    res.json(productDocs);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error: error.message });
  }
});

app.post('/api/products', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { title, description, images, price, category, downloadableFile } = req.body;
    if (!title || !description || !images || !price || !category) {
      return res.status(400).json({ message: 'Missing required product fields' });
    }
    const newProduct = new Product({ title, description, images, price, category, downloadableFile });
    const savedProduct = await newProduct.save();
    res.status(201).json(transformProduct(savedProduct));
  } catch (error) {
    res.status(500).json({ message: 'Error adding product', error: error.message });
  }
});

app.put('/api/products/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid product ID' });
    
    const { wishlisted, ...productData } = req.body;
    
    // Explicitly handle setting downloadableFile to null to allow removal
    const updatePayload = { ...productData };
    if (productData.downloadableFile === null) {
        updatePayload.$unset = { downloadableFile: 1 };
        delete updatePayload.downloadableFile;
    }

    const updatedProduct = await Product.findByIdAndUpdate(id, updatePayload, { new: true });
    
    if (!updatedProduct) return res.status(404).json({ message: 'Product not found' });
    res.json(transformProduct(updatedProduct));
  } catch (error) {
    res.status(500).json({ message: 'Error updating product', error: error.message });
  }
});

app.delete('/api/products/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid product ID' });

    const deletedProduct = await Product.findByIdAndDelete(id);
    if (!deletedProduct) return res.status(404).json({ message: 'Product not found' });

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: 'Error deleting product', error: error.message });
  }
});

app.delete('/api/products', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ message: 'Product IDs are required.' });
    }
    await Product.deleteMany({ _id: { $in: ids } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: 'Error bulk deleting products', error: error.message });
  }
});

// User Wishlist
app.post('/api/users/wishlist/:productId', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.params;
        await User.findByIdAndUpdate(req.user.id, { $addToSet: { wishlist: productId } });
        res.status(200).json({ message: 'Added to wishlist.' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating wishlist', error: error.message });
    }
});
app.delete('/api/users/wishlist/:productId', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.params;
        await User.findByIdAndUpdate(req.user.id, { $pull: { wishlist: productId } });
        res.status(200).json({ message: 'Removed from wishlist.' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating wishlist', error: error.message });
    }
});


// Offers
app.get('/api/offer', async (req, res) => {
  try {
    const offer = await Offer.findOne({ name: 'main-offer' });
    if (!offer) return res.status(404).json({ message: 'Offer configuration not found.' });
    res.json({ isOfferActive: offer.isActive, offerEndTime: offer.endTime ? offer.endTime.getTime() : null });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching offer status', error: error.message });
  }
});

app.post('/api/offer/toggle', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const OFFER_DURATION_MS = 12 * 60 * 60 * 1000;
    const offer = await Offer.findOne({ name: 'main-offer' });
    if (!offer) return res.status(404).json({ message: 'Offer configuration not found.' });

    if (offer.isActive && offer.endTime && offer.endTime > new Date()) {
      offer.isActive = false;
      offer.endTime = null;
    } else {
      offer.isActive = true;
      offer.endTime = new Date(Date.now() + OFFER_DURATION_MS);
    }

    const updatedOffer = await offer.save();
    res.json({ isOfferActive: updatedOffer.isActive, offerEndTime: updatedOffer.endTime ? updatedOffer.endTime.getTime() : null });
  } catch (error) {
    res.status(500).json({ message: 'Error toggling offer', error: error.message });
  }
});

// Orders
const statusDescriptions = {
    'Failed': 'Order payment failed.',
    'Pending': 'The order is awaiting approval.',
    'Pending Payment': 'Payment is pending.',
    'Processing': 'We’re currently preparing your order.',
    'Delivered': 'The order ZIP file has been delivered and is available to download in My Orders.',
    'Refund Accepted': 'A refund request has been approved.',
    'Refunded': 'The payment has been successfully credited back to the customer’s bank/UPI account.',
    'Cancelled': 'The order is cancelled by the user.',
};

app.post('/api/orders', async (req, res) => {
    const { order, userInfo } = req.body;

    if (!userInfo || typeof userInfo !== 'object' || !userInfo.email) {
        return res.status(400).json({ message: 'User information is missing or invalid.' });
    }
    if (!order) {
        return res.status(400).json({ message: 'Order details are missing.' });
    }

    try {
        let user;
        let temporaryPassword = null;
        let responseToken = null;
        let responseUserPayload = null;
        
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token) {
            const decoded = jwt.verify(token, JWT_SECRET);
            user = await User.findById(decoded.id);
            if (!user) return res.status(401).json({ message: 'Invalid session. Please log in again.' });
        } else {
            user = await User.findOne({ email: userInfo.email.toLowerCase() });
            
            if (!user) {
                temporaryPassword = crypto.randomBytes(8).toString('hex');
                const hashedPassword = await bcrypt.hash(temporaryPassword, 12);
                
                user = await User.create({
                    fullName: userInfo.fullName,
                    email: userInfo.email.toLowerCase(),
                    username: userInfo.email.toLowerCase(),
                    password: hashedPassword,
                    role: 'customer',
                    hasTemporaryPassword: true,
                });

                responseUserPayload = constructUserPayload(user);
                responseToken = jwt.sign(responseUserPayload, JWT_SECRET, { expiresIn: '24h' });
            }
        }
        
        const newOrderId = await generateOrderId();
        let newOrderData = {
            orderId: newOrderId,
            user: user._id,
        };

        // Handle Product Order
        if (order.productIds && order.productIds.length > 0) {
            const products = await Product.find({ '_id': { $in: order.productIds } });
            if (products.length !== order.productIds.length) {
                return res.status(400).json({ message: 'One or more products not found.' });
            }

            const totalPrice = products.reduce((sum, p) => sum + p.price, 0);
            const title = products.length === 1 ? products[0].title : `Order of ${products.length} items`;
            const details = products.map(p => p.title).join(', ');
            
            const productWithFile = products.find(p => p.downloadableFile && p.downloadableFile.fileName);

            newOrderData = {
                ...newOrderData,
                planTitle: title,
                planPrice: totalPrice,
                details: details,
                status: 'Delivered',
                timeline: [
                    { status: 'Pending', description: 'Order has been placed.' },
                    { status: 'Processing', description: 'Processing digital product.' },
                    { status: 'Delivered', description: statusDescriptions['Delivered'] }
                ],
                downloadableFile: productWithFile ? productWithFile.downloadableFile : undefined
            };
        } 
        // Handle Service Order
        else if (order.planTitle && order.planPrice != null) {
            newOrderData = {
                ...newOrderData,
                planTitle: order.planTitle,
                planPrice: order.planPrice,
                details: order.details,
                status: 'Pending',
                timeline: [{ status: 'Pending', description: statusDescriptions['Pending'] }]
            };
        } else {
            return res.status(400).json({ message: 'Invalid order data.' });
        }

        const newOrder = new Order(newOrderData);
        const savedOrder = await newOrder.save();

        res.status(201).json({
            message: "Order placed successfully.",
            order: transformOrder(savedOrder),
            token: responseToken,
            user: responseUserPayload,
            temporaryPassword: temporaryPassword,
        });

    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
             return res.status(401).json({ message: 'Invalid session token.' });
        }
        if (error.code === 11000) {
             return res.status(409).json({ message: 'An account with this email already exists.' });
        }
        console.error('Order placement error:', error);
        res.status(500).json({ message: 'Server error during order placement', error: error.message });
    }
});

app.get('/api/orders/my', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.json(orders.map(transformOrder));
    } catch (error) {
        res.status(500).json({ message: 'Error fetching orders', error: error.message });
    }
});

app.put('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { details } = req.body;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order ID' });

        const order = await Order.findById(id);
        if (!order) return res.status(404).json({ message: 'Order not found' });
        if (order.user.toString() !== req.user.id) return res.status(403).json({ message: 'Not authorized' });
        if (order.status !== 'Pending') return res.status(400).json({ message: 'Only pending orders can be updated.' });
        
        order.details = details;
        await order.save();
        
        res.json(transformOrder(order));
    } catch (error) {
        res.status(500).json({ message: 'Error updating order', error: error.message });
    }
});

app.put('/api/orders/:id/cancel', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order ID' });

        const order = await Order.findById(id);
        if (!order) return res.status(404).json({ message: 'Order not found' });
        if (order.user.toString() !== req.user.id) return res.status(403).json({ message: 'Not authorized' });
        if (order.status !== 'Pending') return res.status(400).json({ message: 'Only pending orders can be cancelled.' });

        order.status = 'Cancelled';
        await order.save();

        res.json(transformOrder(order));
    } catch (error) {
        res.status(500).json({ message: 'Error cancelling order', error: error.message });
    }
});

app.get('/api/orders/:id/download', authenticateToken, async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order ID' });

    try {
        const order = await Order.findById(id);
        if (!order) return res.status(404).json({ message: 'Order not found.' });

        if (order.user.toString() !== req.user.id) {
            return res.status(403).json({ message: 'You are not authorized to download this file.' });
        }

        if (!order.downloadableFile || !order.downloadableFile.fileData || !order.downloadableFile.fileName) {
            return res.status(404).json({ message: 'No downloadable file found for this order.' });
        }

        const fileBuffer = Buffer.from(order.downloadableFile.fileData, 'base64');
        
        res.setHeader('Content-Disposition', `attachment; filename="${order.downloadableFile.fileName}"`);
        res.setHeader('Content-Type', 'application/zip');
        res.send(fileBuffer);

    } catch (error) {
        console.error('File download error:', error);
        res.status(500).json({ message: 'Error downloading file', error: error.message });
    }
});

// Admin Order Routes
app.get('/api/admin/orders', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { search, status } = req.query;
        let query = {};

        if (status && status !== 'all') {
            query.status = status;
        }

        if (search) {
            const searchRegex = { $regex: search, $options: 'i' };
            const matchingUsers = await User.find({
                $or: [{ fullName: searchRegex }, { email: searchRegex }],
            }).select('_id');
            const userIds = matchingUsers.map(u => u._id);

            query.$or = [
                { orderId: searchRegex },
                { planTitle: searchRegex },
                { user: { $in: userIds } },
            ];
        }

        const orders = await Order.find(query).sort({ createdAt: -1 }).populate('user', 'fullName email');
        res.json(orders.map(transformOrder));
    } catch (error) {
        res.status(500).json({ message: 'Error fetching orders for admin', error: error.message });
    }
});

app.delete('/api/admin/orders', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { ids } = req.body;
        if (!ids || !Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ message: 'Order IDs are required.' });
        }
        await Order.deleteMany({ _id: { $in: ids } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Error bulk deleting orders', error: error.message });
    }
});

app.put('/api/admin/orders/:id/status', authenticateToken, authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { status, fileName, fileData } = req.body;

    if (!status || !Object.keys(statusDescriptions).includes(status)) {
        return res.status(400).json({ message: 'Invalid status provided.' });
    }
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order ID' });
    
    if (status === 'Delivered' && (!fileName || !fileData)) {
        return res.status(400).json({ message: 'A ZIP file must be uploaded for "Delivered" status.' });
    }

    try {
        const order = await Order.findById(id);
        if (!order) return res.status(404).json({ message: 'Order not found.' });

        order.status = status;
        order.timeline.push({
            status: status,
            description: statusDescriptions[status]
        });

        if (status === 'Delivered') {
            order.downloadableFile = { fileName, fileData };
        }

        const savedOrder = await order.save();
        const populatedOrder = await savedOrder.populate('user', 'fullName email');

        res.json(transformOrder(populatedOrder));
    } catch (error) {
        res.status(500).json({ message: 'Error updating order status', error: error.message });
    }
});

// Public Order Tracking
app.get('/api/orders/track/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        const order = await Order.findOne({ orderId: { $regex: new RegExp(`^${orderId}$`, 'i') } });
        if (!order) return res.status(404).json({ message: 'Order not found.' });
        res.json(transformOrder(order));
    } catch (error) {
        res.status(500).json({ message: 'Error tracking order', error: error.message });
    }
});

// Admin User Management
app.get('/api/admin/users', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { search, status } = req.query;
        const query = {};

        if (search) {
          query.$or = [
            { fullName: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
          ];
        }

        if (status === 'active') {
          query.isActive = true;
        } else if (status === 'inactive') {
          query.isActive = false;
        }

        const users = await User.find(query).sort({ createdAt: -1 });
        res.json(users.map(transformUser));
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
});

app.put('/api/admin/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { fullName, email, contact, newPassword } = req.body;
    
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid user ID.' });
    
    try {
        const userToUpdate = await User.findById(id);
        if (!userToUpdate) return res.status(404).json({ message: 'User not found.' });

        // Apply updates
        if (fullName !== undefined) userToUpdate.fullName = fullName;
        if (email !== undefined) userToUpdate.email = email.toLowerCase();
        if (contact !== undefined) userToUpdate.contact = contact;

        if (newPassword && newPassword.trim().length > 0) {
            userToUpdate.password = await bcrypt.hash(newPassword, 12);
            userToUpdate.hasTemporaryPassword = true;
        }

        const savedUser = await userToUpdate.save();
        
        res.json(transformUser(savedUser));
    } catch (error) {
        if (error.code === 11000) { // Handle duplicate email error
            return res.status(409).json({ message: 'This email is already in use by another account.' });
        }
        res.status(500).json({ message: 'Server error updating user', error: error.message });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid user ID.' });
    
    try {
        if (req.user.id === id) {
            return res.status(400).json({ message: 'You cannot delete your own account.' });
        }
        
        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) return res.status(404).json({ message: 'User not found' });

        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting user', error: error.message });
    }
});

app.delete('/api/admin/users', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { ids } = req.body;
        if (!ids || !Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ message: 'User IDs are required.' });
        }
        
        const filteredIds = ids.filter(id => id !== req.user.id);

        await User.deleteMany({ _id: { $in: filteredIds } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Server error bulk deleting users', error: error.message });
    }
});


// Serve frontend from frontend/dist
app.use(express.static(path.join(__dirname, 'dist')));

// Handle all other routes by sending index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});


// --- Connect to DB and Start Server ---
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✅ Successfully connected to MongoDB.');
    // Ensure seeding is complete before starting the server
    await seedDatabase();
    await seedDemoAdminUser();
    await seedDemoUser();
    await initializeOffer();

    app.listen(PORT, () => {
      console.log(`🚀 Backend server running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    console.error('Ensure MongoDB is running. If MONGO_URI is not in your .env, the default is mongodb://127.0.0.1:27017/nexverra-website');
    process.exit(1);
  });