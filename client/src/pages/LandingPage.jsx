// client/src/pages/LandingPage.jsx
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Microscope, Zap, ShieldCheck, TrendingUp, Cpu, ArrowRight, FileText, Send, Database, Activity, CheckCircle, BarChart3, Brain, Clock } from 'lucide-react';

const LandingPage = () => {
  // Hook to track scroll position for the dynamic header
  const [scrollY, setScrollY] = useState(0);

  useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY);
    window.addEventListener('scroll', handleScroll);

    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  // Placeholder for a detailed particle effect component (if not available, can be removed)
  const FloatingParticles = () => (
    <div className="absolute inset-0 pointer-events-none opacity-50">
      {/* Visual placeholder for animated background elements */}
    </div>
  );

  // --- 1. Header & Navigation ---
  const Nav = () => (
    <header className={`fixed w-full z-50 transition-all duration-300 ${scrollY > 50 ? 'bg-white/95 backdrop-blur-lg shadow-lg' : 'bg-transparent'}`}>
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
        <div className="flex items-center space-x-2 group">
          <div className="relative">
            <Microscope className="w-8 h-8 text-indigo-600 transform group-hover:rotate-12 transition-transform duration-300" />
            <div className="absolute inset-0 bg-indigo-600/20 blur-xl rounded-full group-hover:bg-indigo-600/40 transition-all"></div>
          </div>
          <span className="text-2xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">MalariaLab</span>
        </div>
        <div className="hidden md:flex items-center space-x-8 text-gray-700 font-medium">
          <a href="#features" className="hover:text-indigo-600 transition-colors relative group">
            Features
            <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-indigo-600 group-hover:w-full transition-all duration-300"></span>
          </a>
          <a href="#technology" className="hover:text-indigo-600 transition-colors relative group">
            Technology
            <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-indigo-600 group-hover:w-full transition-all duration-300"></span>
          </a>
          <a href="#contact" className="hover:text-indigo-600 transition-colors relative group">
            Contact
            <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-indigo-600 group-hover:w-full transition-all duration-300"></span>
          </a>
          <Link to="/login"> 
  <button className="px-6 py-2.5 text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-lg shadow-lg hover:shadow-xl hover:scale-105 transition-all duration-300 flex items-center space-x-2">
    <span>Login</span>
    <ArrowRight className="w-4 h-4" />
  </button>
</Link>
          
        </div>
      </nav>
    </header>
  );
  const HeroSection = () => (
    <section className="relative pt-32 pb-24 bg-gradient-to-br from-indigo-50 via-purple-50 to-pink-50 overflow-hidden min-h-screen flex items-center">
      <FloatingParticles />
    
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-gradient-to-br from-indigo-400/20 to-purple-400/20 rounded-full blur-3xl animate-pulse"></div>
      <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-gradient-to-tr from-pink-400/20 to-indigo-400/20 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="text-center space-y-8">
          <div className="inline-flex items-center space-x-2 bg-white/80 backdrop-blur-sm px-4 py-2 rounded-full shadow-lg border border-indigo-100">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-sm font-semibold text-indigo-700">AI-Powered Diagnosis • 99.2% Accuracy</span>
          </div>
          
          <h1 className="text-7xl md:text-8xl font-black text-gray-900 leading-tight">
            Accelerate
            <span className="block bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
              Diagnosis
            </span>
            Save Lives.
          </h1>
          
          <p className="text-2xl text-gray-600 max-w-3xl mx-auto leading-relaxed">
            Transform your lab workflow with <span className="font-semibold text-indigo-600">instantaneous AI detection</span> and real-time patient data management
          </p>
          
          <div className="flex flex-col sm:flex-row justify-center gap-4 pt-4">
            <button className="group px-8 py-4 text-lg font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-xl shadow-2xl hover:shadow-indigo-500/50 hover:scale-105 transition-all duration-300 flex items-center justify-center space-x-2">
              <span>Start Your Free Trial</span>
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            <button className="px-8 py-4 text-lg font-bold text-indigo-700 bg-white/90 backdrop-blur-sm border-2 border-indigo-200 rounded-xl hover:bg-white hover:shadow-xl transition-all duration-300">
              Request a Demo
            </button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-8 max-w-3xl mx-auto pt-12">
            <div className="bg-white/60 backdrop-blur-sm rounded-2xl p-6 shadow-lg border border-white/50">
              <div className="text-4xl font-black text-indigo-600">50,000+</div>
              <div className="text-sm text-gray-600 font-medium mt-1">Tests Processed</div>
            </div>
            <div className="bg-white/60 backdrop-blur-sm rounded-2xl p-6 shadow-lg border border-white/50">
              <div className="text-4xl font-black text-purple-600">99.2%</div>
              <div className="text-sm text-gray-600 font-medium mt-1">AI Accuracy</div>
            </div>
            <div className="bg-white/60 backdrop-blur-sm rounded-2xl p-6 shadow-lg border border-white/50">
              <div className="text-4xl font-black text-pink-600">150+</div>
              <div className="text-sm text-gray-600 font-medium mt-1">Labs Worldwide</div>
            </div>
          </div>
        </div>

        {/* Dashboard Preview */}
        <div className="mt-20 relative">
          <div className="absolute inset-0 bg-gradient-to-r from-indigo-600/20 to-purple-600/20 blur-3xl rounded-3xl transform scale-105"></div>
          <div className="relative bg-white/80 backdrop-blur-xl rounded-3xl shadow-2xl border border-white/50 p-2">
            <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-2xl p-8 min-h-[400px]">
              {/* Mock Dashboard Components */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl p-4 text-white">
                  <Brain className="w-8 h-8 mb-2 opacity-80" />
                  <div className="text-2xl font-bold">AI Detection</div>
                  <div className="text-sm opacity-80">Active</div>
                </div>
                <div className="bg-gradient-to-br from-green-500 to-emerald-600 rounded-xl p-4 text-white">
                  <CheckCircle className="w-8 h-8 mb-2 opacity-80" />
                  <div className="text-2xl font-bold">24 Tests</div>
                  <div className="text-sm opacity-80">Completed Today</div>
                </div>
                <div className="bg-gradient-to-br from-orange-500 to-pink-600 rounded-xl p-4 text-white">
                  <Clock className="w-8 h-8 mb-2 opacity-80" />
                  <div className="text-2xl font-bold">&lt;2s</div>
                  <div className="text-sm opacity-80">Avg Process Time</div>
                </div>
              </div>
              <div className="bg-gray-800/50 rounded-xl p-6 backdrop-blur-sm border border-gray-700">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-white font-semibold">Recent Detections</span>
                  <BarChart3 className="w-5 h-5 text-gray-400" />
                </div>
                <div className="space-y-3">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="flex items-center space-x-3 bg-gray-900/50 rounded-lg p-3">
                      <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-lg"></div>
                      <div className="flex-1">
                        <div className="text-white text-sm font-medium">Patient #{1000 + i}</div>
                        <div className="text-gray-400 text-xs">Positive • {i} parasites detected</div>
                      </div>
                      <div className="text-green-400 text-xs font-semibold">✓ Verified</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );

  const FeatureCard = ({ icon: Icon, title, description, gradient }) => (
    <div className="group relative bg-white rounded-2xl p-8 shadow-lg hover:shadow-2xl transition-all duration-300 border border-gray-100 overflow-hidden">
      <div className={`absolute inset-0 bg-gradient-to-br ${gradient} opacity-0 group-hover:opacity-5 transition-opacity duration-300`}></div>
      <div className={`inline-flex p-4 rounded-2xl bg-gradient-to-br ${gradient} mb-6 transition-transform duration-300`}>
        <Icon className="w-8 h-8 text-white" />
      </div>
      <h3 className="text-2xl font-bold text-gray-900 mb-3">{title}</h3>
      <p className="text-gray-600 leading-relaxed">{description}</p>
    </div>
  );

  // --- 3. Key Value Proposition (Features) ---
  const ValuePropSection = () => (
    <section id="features" className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-5xl font-black text-gray-900 mb-4">
            Why Labs Choose <span className="bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">MalariaLab</span>
          </h2>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            Cutting-edge technology meets clinical precision
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <FeatureCard
            icon={Zap}
            title="Sub-Second Results"
            description="Upload blood slide images and receive instant automated parasite detection with severity analysis powered by YOLO object detection."
            gradient="from-yellow-400 to-orange-500"
          />
          <FeatureCard
            icon={Brain}
            title="AI-Powered Accuracy"
            description="Leverage deep learning models trained on thousands of samples to identify parasites with 99.2% accuracy, minimizing human error."
            gradient="from-indigo-500 to-purple-600"
          />
          <FeatureCard
            icon={Activity}
            title="Real-time Monitoring"
            description="Track test processing status live with Socket.io integration. Receive instant alerts on critical results across your entire lab network."
            gradient="from-green-400 to-emerald-500"
          />
        </div>
      </div>
    </section>
  );

  // --- 4. Workflow Section (with Visual Diagram) ---
  const WorkflowSection = () => (
    <section className="py-24 bg-gradient-to-br from-gray-50 to-indigo-50/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-5xl font-black text-gray-900 mb-4">
            Seamless Workflow Integration
          </h2>
          <p className="text-xl text-gray-600">From intake to diagnosis in four simple steps</p>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          <div className="space-y-8">
            {[
              { 
                icon: FileText, 
                title: '1. Patient Intake', 
                detail: 'Streamlined registration with drag-and-drop sample upload. Automatic patient ID generation.', 
                color: 'from-blue-500 to-indigo-600'
              },
              { 
                icon: Send, 
                title: '2. AI Processing', 
                detail: 'Automated queuing through our dedicated Flask ML service. Detection completes in under 2 seconds per sample.', 
                color: 'from-purple-500 to-pink-600'
              },
              { 
                icon: Database, 
                title: '3. Secure Storage', 
                detail: 'All results stored in encrypted MongoDB with full audit trails. HIPAA-compliant data management.', 
                color: 'from-green-500 to-emerald-600'
              },
              { 
                icon: BarChart3, 
                title: '4. Report & Analytics', 
                detail: 'Real-time performance metrics, trend analysis, and predictive insights via the dashboard. Export reports with one click.', 
                color: 'from-orange-500 to-red-600'
              },
            ].map((item, index) => (
              <div key={index} className="flex items-start space-x-6 group">
                <div className={`flex-shrink-0 w-16 h-16 flex items-center justify-center bg-gradient-to-br ${item.color} rounded-2xl text-white text-2xl font-black shadow-lg transition-all duration-300`}>
                  {index + 1}
                </div>
                <div className="flex-1">
                  <h3 className="text-2xl font-bold text-gray-900 mb-2 transition-colors">{item.title}</h3>
                  <p className="text-gray-600 leading-relaxed">{item.detail}</p>
                </div>
              </div>
            ))}
          </div>
          
          {/* Workflow Diagram Visual */}
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/20 to-purple-500/20 blur-3xl rounded-3xl"></div>
            <div className="relative bg-white rounded-3xl shadow-2xl p-8 border border-gray-100">
              <div className="space-y-6">
                <div className="text-lg font-bold text-gray-900 mb-6">Complete Lab Workflow</div>
                
                {/* Step 1 */}
                <div className="flex items-center space-x-4 p-4 bg-blue-50 rounded-xl border-2 border-blue-200">
                  <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-xl">1</div>
                  <div className="flex-1">
                    <div className="font-semibold text-gray-900">Patient Registration</div>
                    <div className="text-sm text-gray-600">Sample collection & upload</div>
                  </div>
                  <FileText className="w-6 h-6 text-blue-600" />
                </div>

                {/* Arrow */}
                <div className="flex justify-center">
                  <div className="w-0.5 h-8 bg-gradient-to-b from-blue-400 to-purple-400"></div>
                </div>

                {/* Step 2 */}
                <div className="flex items-center space-x-4 p-4 bg-purple-50 rounded-xl border-2 border-purple-200">
                  <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-600 rounded-xl flex items-center justify-center text-white font-bold text-xl">2</div>
                  <div className="flex-1">
                    <div className="font-semibold text-gray-900">AI Analysis</div>
                    <div className="text-sm text-gray-600">YOLO detection in &lt;2s</div>
                  </div>
                  <Brain className="w-6 h-6 text-purple-600" />
                </div>

                {/* Arrow */}
                <div className="flex justify-center">
                  <div className="w-0.5 h-8 bg-gradient-to-b from-purple-400 to-green-400"></div>
                </div>

                {/* Step 3 */}
                <div className="flex items-center space-x-4 p-4 bg-green-50 rounded-xl border-2 border-green-200">
                  <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-green-500 to-emerald-600 rounded-xl flex items-center justify-center text-white font-bold text-xl">3</div>
                  <div className="flex-1">
                    <div className="font-semibold text-gray-900">Results Storage</div>
                    <div className="text-sm text-gray-600">Secure database entry</div>
                  </div>
                  <Database className="w-6 h-6 text-green-600" />
                </div>

                {/* Arrow */}
                <div className="flex justify-center">
                  <div className="w-0.5 h-8 bg-gradient-to-b from-green-400 to-orange-400"></div>
                </div>

                {/* Step 4 */}
                <div className="flex items-center space-x-4 p-4 bg-orange-50 rounded-xl border-2 border-orange-200">
                  <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-orange-500 to-red-600 rounded-xl flex items-center justify-center text-white font-bold text-xl">4</div>
                  <div className="flex-1">
                    <div className="font-semibold text-gray-900">Report & Analytics</div>
                    <div className="text-sm text-gray-600">Real-time dashboard</div>
                  </div>
                  <BarChart3 className="w-6 h-6 text-orange-600" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );

  // --- 5. Trust & Technology ---
  const TrustSection = () => (
    <section id="technology" className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <h2 className="text-5xl font-black text-gray-900 mb-4">
          Enterprise-Grade Infrastructure
        </h2>
        <p className="text-xl text-gray-600 mb-16 max-w-2xl mx-auto">
          Built on proven technologies trusted by healthcare institutions worldwide
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="group bg-gradient-to-br from-indigo-50 to-purple-50 rounded-3xl p-8 hover:shadow-2xl transition-all duration-300 border border-indigo-100">
            <div className="inline-flex p-4 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl mb-6 transition-transform duration-300">
              <TrendingUp className="w-10 h-10 text-white" />
            </div>
            <h3 className="text-2xl font-bold mb-4 text-gray-900">Microservice Architecture</h3>
            <p className="text-gray-600 leading-relaxed">
              Docker-orchestrated **Node.js, Flask, MongoDB, and Redis** stack ensures 99.9% uptime and seamless scalability.
            </p>
          </div>
          <div className="group bg-gradient-to-br from-green-50 to-emerald-50 rounded-3xl p-8 hover:shadow-2xl transition-all duration-300 border border-green-100">
            <div className="inline-flex p-4 bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl mb-6 transition-transform duration-300">
              <ShieldCheck className="w-10 h-10 text-white" />
            </div>
            <h3 className="text-2xl font-bold mb-4 text-gray-900">Military-Grade Security</h3>
            <p className="text-gray-600 leading-relaxed">
              **JWT authentication**, role-based access control, and end-to-end encryption protect patient data at every layer.
            </p>
          </div>
          <div className="group bg-gradient-to-br from-orange-50 to-pink-50 rounded-3xl p-8 hover:shadow-2xl transition-all duration-300 border border-orange-100">
            <div className="inline-flex p-4 bg-gradient-to-br from-orange-500 to-pink-600 rounded-2xl mb-6 transition-transform duration-300">
              <Cpu className="w-10 h-10 text-white" />
            </div>
            <h3 className="text-2xl font-bold mb-4 text-gray-900">24/7 Reliability</h3>
            <p className="text-gray-600 leading-relaxed">
              Automated monitoring, redundant backups, and graceful shutdown mechanisms guarantee continuous operation.
            </p>
          </div>
        </div>
      </div>
    </section>
  );

  // --- 6. Final Call to Action ---
  const CtaSection = () => (
    <section id="contact" className="relative py-24 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-600 via-purple-600 to-pink-600"></div>
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI2MCIgaGVpZ2h0PSI2MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZXIiPjxwYXRoIGQ9Ik0gMTAgMCBMIDAgMCAwIDEwIiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utb3BhY2l0eT0iMC4xIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZ3JpZCkiLz48L3N2ZyA+')] opacity-20"></div>
      
      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-white">
        <h2 className="text-6xl font-black mb-6">
          Ready to Transform Your Lab?
        </h2>
        <p className="text-2xl mb-10 opacity-90 leading-relaxed">
          Join 150+ healthcare facilities already using MalariaLab for faster, more accurate diagnoses
        </p>
        <div className="flex flex-col sm:flex-row justify-center gap-4">
          <button className="group px-10 py-5 text-xl font-bold text-indigo-600 bg-white rounded-2xl shadow-2xl hover:shadow-white/50 hover:scale-105 transition-all duration-300 flex items-center justify-center space-x-3">
            <span>Start Free Trial</span>
            <ArrowRight className="w-6 h-6 group-hover:translate-x-2 transition-transform" />
          </button>
          <button className="px-10 py-5 text-xl font-bold text-white bg-white/10 backdrop-blur-sm border-2 border-white/30 rounded-2xl hover:bg-white/20 transition-all duration-300">
            Schedule Demo
          </button>
        </div>
        <p className="mt-8 text-sm opacity-75">No credit card required • 14-day free trial • Cancel anytime</p>
      </div>
    </section>
  );

  return (
    <div className="font-sans antialiased overflow-x-hidden">
      <Nav />
      <main>
        <HeroSection />
        <ValuePropSection />
        <WorkflowSection />
        <TrustSection />
        <CtaSection />
      </main>
      <footer className="py-12 text-center bg-gray-900 text-gray-400">
        <div className="max-w-7xl mx-auto px-4 space-y-4">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <Microscope className="w-6 h-6 text-indigo-400" />
            <span className="text-xl font-bold text-white">MalariaLab</span>
          </div>
          <p className="text-sm">&copy; {new Date().getFullYear()} MalariaLab System. All rights reserved.</p>
          <div className="flex justify-center space-x-6 text-sm">
              <Link to="/privacy" className="hover:text-white transition">Privacy Policy</Link>
              <Link to="/terms" className="hover:text-white transition">Terms of Service</Link>
              <Link to="/support" className="hover:text-white transition">Support</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;