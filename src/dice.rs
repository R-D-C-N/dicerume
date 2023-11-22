#![allow(dead_code)]

use std::fmt::Display;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Serialize, Deserialize};


#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct DiceExpression {
    inner: Expression
} impl DiceExpression {
    pub fn value(&self, rng: &mut impl rand::Rng, dice_log: &mut Vec<u64>) -> u64 {
        self.inner.value(rng, dice_log)
    }
}
impl Display for DiceExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
enum Expression {
    Integer(u64),
    Dice(Dice),
    Add(Box<Expression>, Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    Mult(Box<Expression>, Box<Expression>),
    Div(Box<Expression>, Box<Expression>),
    Keep(Dice, Condition),
    Success(Dice, Condition),
    Parens(Box<Expression>),
    Nothing,
    Open,
    Close,
} impl Expression {
    fn insert_exp(&mut self, e: Expression) -> bool {
        match self {
            Self::Add(_, s) |
            Self::Sub(_, s) |
            Self::Div(_, s) |
            Self::Mult(_, s) => {
                if s.as_ref() == &Self::Nothing {
                    *s = Box::new(e);
                    true
                } else {
                    false
                }
            }
            _ => {false}
        }
    }
    fn value(&self, rng: &mut impl rand::Rng, dice_log: &mut Vec<u64>) -> u64 {
        match self {
            Self::Add(a, b) => {a.value(rng, dice_log) + b.value(rng, dice_log)}
            Self::Sub(a, b) => {a.value(rng, dice_log) - b.value(rng, dice_log)}
            Self::Div(a, b) => {a.value(rng, dice_log).checked_div(b.value(rng, dice_log)).unwrap_or(0)}
            Self::Mult(a, b) => {a.value(rng, dice_log) * b.value(rng, dice_log)}
            Self::Parens(e) => {e.value(rng, dice_log)}
            Self::Integer(i) => *i,
            Self::Dice(d) => {
                let mut acc = 0;
                for _ in 0..d.quantity {
                    let v = rng.gen_range(1..=d.value);
                    dice_log.push(v);
                    acc += v;
                }
                acc
            }
            Self::Success(d, c) => {
                let mut acc = Vec::new();
                for _ in 0..d.quantity {
                    let v = rng.gen_range(1..=d.value);
                    dice_log.push(v);
                    acc.push(v);
                }
                let acc = c.test(acc);
                acc.len() as u64
            }
            Self::Keep(d, c) => {
                let mut acc = Vec::new();
                for _ in 0..d.quantity {
                    let v = rng.gen_range(1..=d.value);
                    dice_log.push(v);
                    acc.push(v);
                }
                let acc = c.test(acc);
                acc.into_iter().fold(0, |acc, i| acc + i )
            }
            _ => 0
        }
    }
}

impl Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Integer(i) => write!(f, "{i}"),
            Expression::Dice(d) => write!(f, "{d}"),
            Expression::Add(e1, e2) => write!(f, "{e1} + {e2}"),
            Expression::Sub(e1, e2) => write!(f, "{e1} - {e2}"),
            Expression::Mult(e1, e2) => write!(f, "{e1} * {e2}"),
            Expression::Div(e1, e2) => write!(f, "{e1} {e2}"),
            Expression::Keep(d, c) => write!(f, "{d}keep{c}"),
            Expression::Success(d, c) => write!(f, "{d}success{c}"),
            Expression::Parens(e) => write!(f, "({e})"),
            Expression::Nothing => write!(f, "0"),
            Expression::Open => write!(f, "0"),
            Expression::Close => write!(f, "0"),
        }
    }
}

fn expnoth() -> Box<Expression> {
    return Box::new(Expression::Nothing);
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
struct Dice {
    quantity: u64,
    value: u64
}
impl Display for Dice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.quantity == 1 {
            write!(f, "d{}", self.value)
        } else {
            write!(f, "{}d{}", self.quantity, self.value)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
enum Condition {
    Greater(u64),
    Less(u64),
    Equal(u64),
    Between(u64,u64),
    Min(u64),
    Max(u64)
}
impl Condition {
    fn test(&self, mut v: Vec<u64>) -> Vec<u64> {
        match self {
            Condition::Greater(i) => v.retain(|v| v > i),
            Condition::Less(i) => v.retain(|v| v < i),
            Condition::Equal(i) => v.retain(|v| v == i),
            Condition::Between(a, b) => v.retain(|v| (a..=b).contains(&v)),
            Condition::Min(n) => {
                v.sort();
                v = v.into_iter().take(*n as usize).collect();
            }
            Condition::Max(n) => {
                v.sort();
                v = v.into_iter().rev().take(*n as usize).collect();
            },
        }
        v
    }
}
impl Display for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Greater(i) => write!(f, ">{i}"),
            Self::Less(i) => write!(f, "<{i}"),
            Self::Equal(i) => write!(f, "={i}"),
            Self::Between(a, b) => write!(f, "{a},{b}"),
            Self::Min(i) => write!(f, "min{i}"),
            Self::Max(i) => write!(f, "max{i}"),
        }
    }
}

const REGEX_STR: &str = r"(\d*d\d+[ks](?:l|h|>|<|=|\d+, *)\d+)|(\d*d\d+)|(\+|\-|\/|\*|\(|\))|(\d+)";
static REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(REGEX_STR).unwrap());

fn tokens(s: &str) -> Vec<Expression> {
    let mut fin = Vec::new();
    for i in REGEX.captures_iter(s) {
        if let Some(m) = i.get(1) {
            let m = m.as_str();
            let s: Vec<_> = m.splitn(2, 'k').collect();
            let d = eval_dice(s[0]);
            let c = match s[1].chars().nth(0).unwrap() {
                '0'..='9' => {
                    let mut n = s[1].split(',');
                    let mut min = n.next().unwrap().parse().unwrap();
                    let mut max = n.next().unwrap().parse().unwrap();
                    if min > max {
                        std::mem::swap(&mut min, &mut max)
                    }
                    Condition::Between(min, max)
                }
                c => {
                    let n = s[1][1..].parse().unwrap();
                    match c {
                        'l' => {Condition::Min(n)}
                        'h' => {Condition::Max(n)}
                        '>' => {Condition::Greater(n)}
                        '<' => {Condition::Less(n)}
                        '=' => {Condition::Equal(n)}
                        c => {panic!("unexpected dice condition '{c}'");}
                    }
                }
            };
            if m.contains('k') {
                fin.push(Expression::Keep(d, c));
            } else {
                fin.push(Expression::Success(d, c));
            }
        } else if let Some(m) = i.get(2) {
            fin.push(Expression::Dice(eval_dice(m.as_str())));
        } else if let Some(m) = i.get(3) {
            let e = match m.as_str().chars().nth(0).unwrap() {
                '+' => Expression::Add(expnoth(), expnoth()),
                '-' => Expression::Sub(expnoth(), expnoth()),
                '/' => Expression::Div(expnoth(), expnoth()),
                '*' => Expression::Mult(expnoth(), expnoth()),
                '(' => Expression::Parens(Box::new(Expression::Open)),
                ')' => Expression::Parens(Box::new(Expression::Close)),
                s => panic!("Unexpected symbol '{s}'")
            };
            fin.push(e);
        } else if let Some(m) = i.get(4) {
            fin.push(Expression::Integer(m.as_str().parse().unwrap()));
        }
    }
    return fin;
}

fn eval_dice(s: &str) -> Dice {
    let s: Vec<_> = s.split('d').collect();
    let c = if s[0].len() > 0 {
        s[0].parse().unwrap()
    } else {
        1u64
    };
    let mut v = s[1].parse().unwrap();
    if v < 2 {v = 2;}
    Dice { quantity: c, value: v }
}

fn combine_down_tokens(exps: &mut dyn Iterator<Item = Expression>, inner: bool) -> Option<DiceExpression> {
    let mut fin = exps.next()?;
    if !matches!(fin, Expression::Integer(..) | Expression::Dice(..) | Expression::Keep(..) | Expression::Success(..)) {return None;}
    while let Some(exp) = exps.next() {
        match exp {
            Expression::Add(..) => {
                fin = Expression::Add(Box::new(fin), expnoth());
            }
            Expression::Sub(..) => {
                fin = Expression::Sub(Box::new(fin), expnoth());
            }
            Expression::Div(..) => {
                fin = Expression::Div(Box::new(fin), expnoth());
            }
            Expression::Mult(..) => {
                fin = Expression::Mult(Box::new(fin), expnoth());
            }
            e @ Expression::Integer(..) |
            e @ Expression::Dice(..) |
            e @ Expression::Success(..) |
            e @ Expression::Keep(..) => {
                if fin.insert_exp(e) {
                    continue;
                } else {
                    return None;
                }
            }
            Expression::Parens(i) => {
                match i.as_ref() {
                    Expression::Open => {
                        let e = combine_down_tokens(exps, true)?;
                        fin.insert_exp(Expression::Parens(e.inner.into()));
                    }
                    Expression::Close => {
                        if inner {
                            return Some(DiceExpression { inner: fin });
                        }
                    }
                    _ => {panic!("unexpected expression {i:?}")}
                }
            }
            _ => {panic!("unexpected expression {exp:?}")}
        }
    }
    Some(DiceExpression { inner: fin })
}

pub fn make_dice_expression(s: &str) -> Option<DiceExpression> {
    let t = tokens(s);
    let mut it = t.into_iter();
    combine_down_tokens(&mut it, false)
}

#[cfg(test)]
pub mod test {
    use rand::thread_rng;

    use super::make_dice_expression;

    #[test]
    fn test_parse() {
        let basic = "5d10+5-2d8kl1";
        let exp1 = make_dice_expression(basic).unwrap();
        let f = format!("{}", exp1);
        assert_eq!(f, "5d10 + 5 - 2d8keepmin1");
        let parens = "1+(1+1d5+(3*5))+(5)";
        let exp2 = make_dice_expression(parens).unwrap();
        let f = format!("{}", exp2);
        assert_eq!(f, "1 + (1 + d5 + (3 * 5)) + (5)");
        let mut rng = thread_rng();
        let mut log = Vec::new();
        let v1 = exp1.value(&mut rng, &mut log);
        let v2 = exp2.value(&mut rng, &mut log);
        println!("v1: {v1} v2: {v2} log: {log:?}");
        assert!((2..=54u64).contains(&&v1));
        assert!((23..=27u64).contains(&&v2));
    }
}