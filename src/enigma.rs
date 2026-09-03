//! Simulation of the WWII Wehrmacht Enigma I cipher machine.

#[derive(Clone)]
pub struct Rotor {
    wiring: [u8; 26],
    inverse_wiring: [u8; 26],
    notch: u8,
    position: u8,
    ring_setting: u8,
}

impl Rotor {
    pub fn new(wiring_str: &str, notch_char: char, ring_setting: u8) -> Self {
        let mut wiring = [0u8; 26];
        let mut inverse_wiring = [0u8; 26];

        for (i, c) in wiring_str.chars().enumerate() {
            let target = (c.to_ascii_uppercase() as u8) - b'A\;
            wiring[i] = target;
            inverse_wiring[target as usize] = i as u8;
        }

        Self {
            wiring,
            inverse_wiring,
            notch: (notch_char.to_ascii_uppercase() as u8) - b'A\,
            position: 0,
            ring_setting: ring_setting % 26,
        }
    }

    pub fn rotor_i() -> Self {
        Self::new("EKMFLGDQVZNTOWYHXUSPAIBRCJ", 'Q\, 0)
    }

    pub fn rotor_ii() -> Self {
        Self::new("AJDKSIRUXBLHWTMCQGZNPYFVOE", 'E\, 0)
    }

    pub fn rotor_iii() -> Self {
        Self::new("BDFHJLCPRTXVZNYEIWGAKMUSQO", 'V\, 0)
    }

    pub fn set_position(&mut self, pos: char) {
        self.position = (pos.to_ascii_uppercase() as u8) - b'A\;
    }

    pub fn is_at_notch(&self) -> bool {
        self.position == self.notch
    }

    pub fn step(&mut self) {
        self.position = (self.position + 1) % 26;
    }

    pub fn forward(&self, input: u8) -> u8 {
        let shift = (self.position + 26 - self.ring_setting) % 26;
        let index = (input + shift) % 26;
        let pin = self.wiring[index as usize];
        (pin + 26 - shift) % 26
    }

    pub fn backward(&self, input: u8) -> u8 {
        let shift = (self.position + 26 - self.ring_setting) % 26;
        let index = (input + shift) % 26;
        let pin = self.inverse_wiring[index as usize];
        (pin + 26 - shift) % 26
    }
}

pub struct Reflector {
    wiring: [u8; 26],
}

impl Reflector {
    pub fn reflector_b() -> Self {
        let mut wiring = [0u8; 26];
        for (i, c) in "YRUHQSLDPXNGOKMIEBFZCWVJAT".chars().enumerate() {
            wiring[i] = (c as u8) - b'A\;
        }
        Self { wiring }
    }

    pub fn reflect(&self, input: u8) -> u8 {
        self.wiring[(input % 26) as usize]
    }
}

pub struct Plugboard {
    mapping: [u8; 26],
}

impl Plugboard {
    pub fn new(pairs: &str) -> Self {
        let mut mapping = [0u8; 26];
        for i in 0..26 {
            mapping[i] = i as u8;
        }

        for pair in pairs.split_whitespace() {
            let bytes = pair.as_bytes();
            if bytes.len() == 2 {
                let a = (bytes[0].to_ascii_uppercase() - b'A\) as usize;
                let b = (bytes[1].to_ascii_uppercase() - b'A\) as usize;
                if a < 26 && b < 26 {
                    mapping[a] = b as u8;
                    mapping[b] = a as u8;
                }
            }
        }

        Self { mapping }
    }

    pub fn swap(&self, input: u8) -> u8 {
        self.mapping[(input % 26) as usize]
    }
}

pub struct EnigmaMachine {
    pub left_rotor: Rotor,
    pub middle_rotor: Rotor,
    pub right_rotor: Rotor,
    pub reflector: Reflector,
    pub plugboard: Plugboard,
}

impl EnigmaMachine {
    pub fn new(left: Rotor, middle: Rotor, right: Rotor, reflector: Reflector, plugboard: Plugboard) -> Self {
        Self {
            left_rotor: left,
            middle_rotor: middle,
            right_rotor: right,
            reflector,
            plugboard,
        }
    }

    fn step_rotors(&mut self) {
        let right_at_notch = self.right_rotor.is_at_notch();
        let middle_at_notch = self.middle_rotor.is_at_notch();

        if middle_at_notch {
            self.middle_rotor.step();
            self.left_rotor.step();
        } else if right_at_notch {
            self.middle_rotor.step();
        }

        self.right_rotor.step();
    }

    pub fn process_char(&mut self, c: char) -> char {
        if !c.is_ascii_alphabetic() {
            return c;
        }

        self.step_rotors();

        let mut signal = (c.to_ascii_uppercase() as u8) - b'A\;
        signal = self.plugboard.swap(signal);

        signal = self.right_rotor.forward(signal);
        signal = self.middle_rotor.forward(signal);
        signal = self.left_rotor.forward(signal);

        signal = self.reflector.reflect(signal);

        signal = self.left_rotor.backward(signal);
        signal = self.middle_rotor.backward(signal);
        signal = self.right_rotor.backward(signal);

        signal = self.plugboard.swap(signal);

        let out = (b'A\ + signal) as char;
        if c.is_ascii_lowercase() {
            out.to_ascii_lowercase()
        } else {
            out
        }
    }

    pub fn process_string(&mut self, text: &str) -> String {
        text.chars().map(|c| self.process_char(c)).collect()
    }
}
