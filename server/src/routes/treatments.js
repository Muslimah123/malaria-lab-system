// server/src/routes/treatments.js
const express = require('express');
const treatmentController = require('../controllers/treatmentController');
const { auth } = require('../middleware/auth');

const router = express.Router();
router.use(auth);

router.post('/',                              treatmentController.createTreatment.bind(treatmentController));
router.get('/followups',                      treatmentController.getUpcomingFollowups.bind(treatmentController));
router.get('/test/:testId',                   treatmentController.getByTestId.bind(treatmentController));
router.get('/patient/:patientId',             treatmentController.getByPatient.bind(treatmentController));
router.patch('/:treatmentId/outcome',         treatmentController.updateOutcome.bind(treatmentController));

module.exports = router;
