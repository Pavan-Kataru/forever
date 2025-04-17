import express from 'express'
import {placeOrder, placeOrderStripe, placeOrderRazorpay, allOrders, userOrders, updateStatus, verifyStripe} from '../controllers/orderController.js'
import admimAuth from '../middleware/adminAuth.js'
import authUser from '../middleware/auth.js'

const orderRouter =  express.Router()

//Admin features
orderRouter.post('/list',admimAuth, allOrders)
orderRouter.post('/status',admimAuth, updateStatus)

//Payment features
orderRouter.post('/place',authUser,placeOrder)
orderRouter.post('/stripe',authUser,placeOrderStripe)
orderRouter.post('/razorpay',authUser,placeOrderRazorpay)

//user feature
orderRouter.post('/userorders', authUser,userOrders)

//verify payment
orderRouter.post('/verifyStripe',authUser, verifyStripe)


export default orderRouter




